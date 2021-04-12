def parse_equation(coefficients: str):
    """
    Create a callable function representing an equation
    Function in form of:

        ["a, b, ... , z"] -> f(x) = (a * x) ... (y * x ^ ?) + z
                                 ...
        ["a, b"]          -> f(x) = (a * x) + b
        ["a"]             -> f(x) = a

    :param coefficients: CSV in string form of the coefficients
    :return: A callable function that calculates a polynomial of variable degree, based on given coefficients
    """
    # Equations exists as coefficients to a len(coefficients) degree polynomial
    list_of_coefficients = coefficients.replace(" ", "").split(",")
    list_of_expressions = []
    degree = len(list_of_coefficients)
    current_degree = 1

    # Escape on no coefficients
    if degree == 0 or list_of_coefficients[0] == '':
        return lambda x: 0

    # Loop through coefficients, assigning them to their respective expressions based on degree
    for coefficient in list_of_coefficients:
        if current_degree == degree:
            # Final value is always a constant (C)
            list_of_expressions.append(lambda x, cof=coefficient: float(cof))
        else:
            list_of_expressions.append(lambda x, cof=coefficient, deg=current_degree: float(cof) * pow(x, deg))
        current_degree += 1

    # Return a function that sums up the value of each expression
    return lambda x: sum(list(map(lambda y: y(x), list_of_expressions)))
