# qingping-prometheus-exporter

![Python Version](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-GNU%20GPL%20v3-blue)

## Features

This is a simple Prometheus exporter for Qingping air quality sensors.

Currently supported measurements:
- CO₂ (Carbon Dioxide)
- PM2.5 (Fine particulate matter)
- TVOC (Total Volatile Organic Compounds)
- Temperature
- Humidity

Note: At this time, the workflow only supports data from Qingping Cloud services.

## Prerequisite

- Python 3.12+
- Qingping air monitor (for example, [Qingping Air Monitor](https://www.qingping.co/air-monitor/overview))

## Configuration

Connect the Qingping Air monitor to the Qingping+ app.
Generate a Qingping Developer API token from [developer.qingping.co/personal/permissionApply | Access Management | Apply Access](https://developer.qingping.co/personal/permissionApply)

## Usage 
```
docker build -t qingping-prometheus-exporter .
```
```
docker run -d --name qingping-prometheus-exporter -p 9876:9876 -e QINGPING_CLIENT_ID=your-client-id -e QINGPING_CLIENT_SECRET=your-client-secret qingping-prometheus-exporter .
```


## Example metrics

```
# HELP qingping_sensor_value Sensor value
# TYPE qingping_sensor_value gauge
qingping_sensor_value{device="Office Air Monitor",mac="XXX",type="co2",unit="ppm"} 649
qingping_sensor_value{device="Office Air Monitor",mac="XXX",type="pm25",unit="ug/m3"} 17
qingping_sensor_value{device="Office Air Monitor",mac="XXX",type="tvoc",unit="ppb"} 1297
qingping_sensor_value{device="Office Air Monitor",mac="XXX",type="humidity",unit="%"} 36.6
qingping_sensor_value{device="Office Air Monitor",mac="XXX",type="temperature",unit="C"} 23.6
```