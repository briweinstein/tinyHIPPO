import json
import sqlite3
import statistics
import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit
from packet_analysis.sql.sql_helper import get_values, get_count, create_connection


def get_hourly_average(conn: sqlite3.Connection, table: str, adjust_for_zero=False):
    collection = {}
    averaged_data = []
    averaged_deviation = []
    total_days = set()

    segments = 2
    for x in range(24):  # Hour loop
        for y in range(segments):
            segment = round(y / segments, 2)

            # Set bounds of the
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

            for day in days:
                count = values.count(day)
                key = x + segment
                if key in collection:
                    collection[key].append(count)
                else:
                    collection[key] = [count]

    for x in collection:
        segment_values = collection[x]
        segment_values_length = len(segment_values)

        # Pack with zeros for missing days, in order to get a true average
        if segment_values_length < len(total_days):
            for y in range(len(total_days) - segment_values_length):
                segment_values.append(0)

        mean = statistics.mean(segment_values)
        deviation = statistics.pstdev(segment_values)

        averaged_data.append((x, mean))
        averaged_deviation.append((x, deviation))

    return averaged_data, averaged_deviation


# Fifth degree polynomial function
def objective(x, a, b, c, d, e, f, g, h):
    return (a * x) + (b * x ** 2) + (c * x ** 3) + (d * x ** 4) + (e * x ** 5) + (f * x ** 6) + (g * x ** 7) + h

def polynomial_fit_function(x_data: list, y_data: list):
    params, params_covariance = curve_fit(objective, x_data, y_data)
    a, b, c, d, e, f, g, h = params
    plt.scatter(x_data, y_data)
    x_line = np.arange(min(x_data), max(x_data), 1)
    # calculate the output for the range
    y_line = objective(x_line, a, b, c, d, e, f, g, h)
    # create a line plot for the mapping function
    plt.plot(x_line, y_line, '--', color='red')
    plt.show()
