import sys
import os

sys.path.insert(0, os.path.abspath("../.."))
import sqlite3
import argparse
import statistics
from scipy.optimize import curve_fit
from src.database.models import AnomalyEquations
from packet_analysis.sql.sql_helper import get_values, create_connection


def get_segmented_average(conn: sqlite3.Connection, table: str, adjust_for_zero=False, segments=2):
    """
    Create lists of averages over a 24 hour time period, segmented if desired
    :param conn: Database connection
    :param table: Table to pull data from
    :param adjust_for_zero: Adjust for zero in calculations (Prevents unrealistic averages in low quantity data sets)
    :param segments: Number of segments (Data points) per hour
    :return: List of averages, list of deviations
    """
    collection = {}
    averaged_data = []
    averaged_deviation = []
    total_days = set()

    # Loop through the hours in a day
    for x in range(24):
        # Loop through the segments
        for y in range(segments):
            segment = round(y / segments, 2)

            # Set bounds of the segment
            lower_bound = x + segment
            upper_bound = x + round((y + 1) / segments, 2)
            values = get_values(
                conn, table, ["day"], ["hour >= {0}".format(lower_bound),
                                       "hour < {0}".format(upper_bound)])

            # Loop through the list of returned values, separate by day
            days = set(values)
            total_days |= days
            if adjust_for_zero:
                collection[x + segment] = []

            # Loop through the days, create a collection keyed on segment time, filled with data from each day
            for day in days:
                count = values.count(day)
                key = x + segment
                if key in collection:
                    collection[key].append(count)
                else:
                    collection[key] = [count]

    # Loop through the values added to the collection
    for x in collection:
        segment_values = collection[x]
        segment_values_length = len(segment_values)

        # Pack with zeros for missing days, in order to get a true average
        if segment_values_length < len(total_days):
            for y in range(len(total_days) - segment_values_length):
                segment_values.append(0)

        # Calculate the mean and deviation
        mean = statistics.mean(segment_values)
        deviation = statistics.pstdev(segment_values)

        # Append this information as tuples [(x, y) values]
        averaged_data.append((x, mean))
        averaged_deviation.append((x, deviation))

    # Return lists of (x, y) data for average and deviation
    return averaged_data, averaged_deviation


# Seventh degree polynomial function
def objective(x, a, b, c, d, e, f, g, h):
    """
    Objective function for the curve_fit to use
    :param x: Input to function
    :param a, b, c, d, e, f, g, h: Coefficients of sub expressions
    :return: Value calculated from function
    """
    return (a * x) + (b * x ** 2) + (c * x ** 3) + (d * x ** 4) + (e * x ** 5) + (f * x ** 6) + (g * x ** 7) + h


def polynomial_fit_function(x_data: list, y_data: list):
    """
    Function used to fit a polynomial function to the data
    :param x_data: X values
    :param y_data: Y values
    :return: Parameter to the function
    """
    params = curve_fit(objective, x_data, y_data)[0]
    return params


def main(argv):
    """
    Entry point for the program, creates equations from the given .db file,
    sends them to SQLite DB designated in config.py file
    :param argv: Arguments for program
    """
    parser = argparse.ArgumentParser(description="Analyzes PCAP information and stores it in a SQL database")
    parser.add_argument("database_path", nargs=1, type=str, help="Path for the database file to export data to")

    args = parser.parse_args(argv[1:])

    # Layers to create the equations for
    layers = ["ARP", "IP", "UDP", "TCP", "DNS", "DHCP"]  # Not enough data for EAPOL

    # Analysis data dump to create equations from
    analysis_connection = create_connection(args.database_path[0])

    # Create the average and deviation equations for each layer
    for layer in layers:
        # Calculate the averages and deviation
        avg, dev = get_segmented_average(analysis_connection, layer)

        # Separate x and y values
        x_avg = [val[0] for val in avg]
        y_avg = [val[1] for val in avg]
        x_dev = [val[0] for val in dev]
        y_dev = [val[1] for val in dev]

        # Fit a polynomial equation to the data
        avg_coefficients = list(map(lambda x: "%f" % round(x, 5), polynomial_fit_function(x_avg, y_avg)))
        dev_coefficients = list(map(lambda x: "%f" % round(x, 5), polynomial_fit_function(x_dev, y_dev)))

        # Create rows for DB insertion, default window and interval size
        object = AnomalyEquations(average_equation=", ".join(avg_coefficients),
                                  deviation_equation=", ".join(dev_coefficients),
                                  layer=layer,
                                  window_size=3600,
                                  interval_size=600)
        object.insert_new_object(object)


if __name__ == "__main__":
    main(sys.argv)
