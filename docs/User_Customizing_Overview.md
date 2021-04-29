# Algorithm Overview
Anomaly detection based signatures use a sliding window algorithm to evaluate frequencies for a specific time window. The algorithms generated and entered by the user are what defines the threshold for alerting in the signature. The abstract signatures are set to calculate and adjust frequency counts based on the given interval and window size, and will alert when the calculated threshold is less than the current frequency. The window slides at set intervals (Default 10 minutes) during which the average and deviation for that new window is generated and the data from the oldest interval is expunged.

## Input Dissection
The input analysis program can be run in order to dissect captured data into usable information, and inserts it into a permanent DB. This greatly decreases processing times and allows for much larger sets of data to be used than just storing in memory. This is why the intent for this program and the equation generation program is that it is run offline, on some device other than the router so that it has reasonable processing times.

## Equation Generation
The equations generated from the data will be in the form of a fifth degree polynomial that is representative of the average frequency of traffic from the dataset and the deviations, with averages being made in 30 minute intervals. These two metrics will then have a curve fit to a plot of their respective values, using a standard 5th degree polynomial as the objective. Once this curve fit equation is generated, it will then have its coefficients extracted to be stored as the external representation of the equation. The coefficients are efficient to store and input, and because the equation format is standardized it makes reassembly within tinyHIPPO simple as well.

## Input From User
The user is able to run these programs locally or on a machine besides the router and use the UI for a more simplified insertion of additional equations. By providing the coefficient output from the equation generation program, the UI will be able to insert the equation into the DB for the user. These equations will then be inserted as a part of the AnomalyEngine on startup.
