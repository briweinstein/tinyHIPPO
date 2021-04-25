INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-189.354791448612, 53.144440774391, -5.143383409207, 0.197926551954, -0.002547069599, 1275.989138879561',
              '85.823806496294, -25.313816132750, 2.385953117981, -0.085394382754, 0.000940534145, 632.473945055302',
              'ARP',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='ARP');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-1498.262632812481, 370.035386661542, -34.861580373445, 1.372394409049, -0.018870821226, 6481.415780402496',
              '-1124.771103279209, 206.137781453163, -18.442848305159, 0.811224696801, -0.013839794255, 4957.014459697217',
              'IP',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='IP');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-1102.799027369906, 264.406836430741, -24.873707729857, 0.993107287736, -0.014041518634, 4017.763051682753',
              '-1475.860194036466, 298.193150389046, -27.295645354517, 1.160383651569, -0.018572383575, 4022.362054515947',
              'UDP',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='UDP');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-178.939734995289, 46.515599140359, -4.343388549005, 0.164269371752, -0.002094129666, 997.968122936364',
              '-5.392765746895, -6.161625031307, 0.821576308992, -0.032271654295, 0.000338912312, 596.106368816697',
              'TCP',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='TCP');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-1.030042343676, 0.274258522937, -0.028144289920, 0.001217900824, -0.000018716763, 2.716645360057',
              '-0.982038140597, 0.302099694330, -0.034618237391, 0.001625147995, -0.000026694500, 3.239917901155',
              'DNS',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='DNS');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '-0.276818504481, 0.109974013391, -0.013403959342, 0.000642424174, -0.000010529718, 1.015540049853',
              '-0.140559679905, 0.081755221457, -0.010238891207, 0.000432983744, -0.000005361709, 1.648713155823',
              'DHCP',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='DHCP');
INSERT INTO anomaly_equations (average_equation, deviation_equation, layer, window_size, interval_size)
            SELECT
              '0.644005180824, -0.132204815438, 0.011357037395, -0.000487448787, 0.000008391762, 3.985396601765',
              '3.889392068795, -0.993880270552, 0.095657625055, -0.003973535958, 0.000059895703, 1.528570743965',
              'NTPHeader',
              '3600',
              '600'
            WHERE NOT EXISTS (SELECT * FROM anomaly_equations WHERE layer='NTPHeader');

