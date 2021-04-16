BEGIN TRANSACTION;
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '80.932890, -146.879960, 41.430610, -5.012090, 0.302950, -0.009020, 0.000110, 1077.925060',
              '10.857100, -8.156670, 2.521500, -0.335490, 0.021860, -0.000690, 0.000010, 737.960530',
              'ARP',
              '3600',
              '600'
            );
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '-1027.202070, -120.130200, 85.864370, -12.571050, 0.821750, -0.025470, 0.000300, 5874.096260',
              '-2764.718640, 977.783860, -166.910030, 15.455970, -0.793790, 0.021250, -0.000230, 5892.222710',
              'IP',
              '3600',
              '600'
            );
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '-1131.377730, 140.912800, 11.080900, -3.532660, 0.277980, -0.009370, 0.000120, 3797.561030',
              '-3203.066620, 1163.417510, -203.066680, 19.102590, -0.991590, 0.026730, -0.000290, 4844.858720',
              'UDP',
              '3600',
              '600'
            );
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '16.754460, -97.160320, 28.526210, -3.446610, 0.206110, -0.006060, 0.000070, 855.197550',
              '-52.920180, 2.066690, 1.531930, -0.232540, 0.013680, -0.000370, 0.000000, 666.750400',
              'TCP',
              '3600',
              '600'
            );
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '0.413170, -0.394920, 0.096280, -0.010940, 0.000640, -0.000020, 0.000000, 2.182640',
              '1.754940, -0.929740, 0.192890, -0.020700, 0.001200, -0.000040, 0.000000, 3.005310',
              'DNS',
              '3600',
              '600'
            );
INSERT INTO anomaly_equations (id, average_equation, deviation_equation, layer, window_size, interval_size)
            VALUES (
              NONE,
              '0.839580, -0.196660, 0.000730, 0.003640, -0.000390, 0.000020, -0.000000, 0.342670',
              '-0.180460, 0.622250, -0.217840, 0.030730, -0.002110, 0.000070, -0.000000, 1.404950',
              'DHCP',
              '3600',
              '600'
            );
COMMIT;