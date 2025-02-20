import http.client
import urllib.parse
import os
import base64
import json
import time
import logging
import logging.handlers
from http.client import HTTPException
from urllib.error import URLError
from socket import error as SocketError
from typing import Optional, Dict, Any, List, Tuple
import http.server
import threading
import argparse
import sys

class QingpingClient:
    """
    Client for Qingping (Cleargrass) Cloud API.
    
    This client handles authentication and communication with the Qingping Cloud API,
    providing access to device data and measurements.
    """

    def __init__(self, client_id: str, client_secret: str, temp_directory: str):
        """
        Initialize Qingping API client.
        
        Args:
            client_id: OAuth client ID obtained from Qingping developer portal
            client_secret: OAuth client secret obtained from Qingping developer portal
            temp_directory: Directory for caching access tokens
            
        Raises:
            ValueError: If client_id or client_secret is missing
        """
        if not client_id or not client_secret:
            raise ValueError("client_id and client_secret are required")

        self._client_id = client_id
        self._client_secret = client_secret
        self._temp_directory = temp_directory
        self._oauth_host = 'oauth.cleargrass.com'
        self._api_host = 'apis.cleargrass.com'
        self._access_token = None
        
        if not os.path.exists(self._temp_directory):
            os.makedirs(self._temp_directory)

        self.logger = logging.getLogger('QingpingClient')

    def get_devices(self) -> Dict[str, Any]:
        """
        Get list of user's devices and their latest data.
        
        Retrieves information about all devices associated with the account,
        including their latest sensor measurements.
        
        Returns:
            Dict[str, Any]: Response containing device list and their data
                Format:
                {
                    "devices": [
                        {
                            "info": {
                                "name": str,
                                "mac": str,
                                "type": str,
                                ...
                            },
                            "data": {
                                "temperature": {"value": float},
                                "humidity": {"value": float},
                                "co2": {"value": float},
                                "pm25": {"value": float},
                                "tvoc": {"value": float},
                                "timestamp": {"value": int}
                            }
                        },
                        ...
                    ]
                }
            
        Raises:
            Exception: On network or API errors
        """
        self.logger.debug("Fetching devices data")
        response = self._make_api_request("GET", "/v1/apis/devices")
        self.logger.debug("Successfully fetched data for %d devices", len(response.get('devices', [])))
        return response

    def _make_api_request(self, method: str, path: str, payload: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make an authenticated request to the Qingping API.
        
        Handles token management and request execution.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Optional request body data
            
        Returns:
            Dict[str, Any]: JSON response from the API
            
        Raises:
            Exception: On request or response errors
        """
        access_token = self._ensure_valid_token()
        
        self.logger.debug("Making %s request to %s", method, path)
        conn = http.client.HTTPSConnection(self._api_host)
        try:
            headers = {
                'Authorization': f"Bearer {access_token}",
                'Content-Type': 'application/json'
            }
            
            if payload:
                body = json.dumps(payload)
                self.logger.debug("Request payload: %s", body)
            else:
                body = None
                
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            
            if response.status != 200:
                error_body = response.read().decode('utf-8')
                if response.status == 401:
                    self.logger.warning("Access token expired, retrying with new token")
                    self._access_token = None
                    return self._make_api_request(method, path, payload)
                else:
                    self.logger.error("API request failed (status %d): %s", response.status, error_body)
                    raise Exception(f"API request failed: {error_body}")
            
            return self._handle_response(response)
            
        except (HTTPException, URLError, SocketError) as e:
            self.logger.error("Network error: %s", e)
            raise
        finally:
            conn.close()

    def _handle_response(self, response) -> Dict[str, Any]:
        """
        Process HTTP response from the API.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dict[str, Any]: Parsed JSON response if present, empty dict if no content
            
        Raises:
            Exception: On response errors
        """
        if response.status == 200:
            content_type = response.getheader('Content-Type')
            if not content_type:
                self.logger.debug("Empty response received")
                return {}
                
            if not content_type.startswith('application/json'):
                error_msg = f"Unexpected Content-Type: {content_type}"
                self.logger.error(error_msg)
                raise Exception(error_msg)
                
            data = response.read()
            try:
                result = json.loads(data.decode("utf-8"))
                self.logger.debug("Successfully parsed JSON response")
                return result
            except json.JSONDecodeError as e:
                error_msg = f"Failed to decode JSON response: {e}"
                self.logger.error(error_msg)
                raise Exception(error_msg)
        elif response.status == 401:
            self.logger.warning("Token expired, resetting and retrying")
            self._access_token = None
            return self.get_devices()
        else:
            error_msg = f"API request failed. Status: {response.status}"
            self.logger.error(error_msg)
            raise Exception(error_msg)

    def _ensure_valid_token(self) -> str:
        """
        Ensure a valid access token is available.
        
        Checks cache for valid token, fetches new one if needed.
        
        Returns:
            str: Valid access token
        """
        self.logger.debug("Ensuring valid access token")
        if not self._access_token:
            self.logger.debug("No token in memory, checking cache")
            self._access_token = self._read_token_from_cache()
        
        if not self._access_token:
            self.logger.debug("No valid token in cache, fetching new one")
            token_response = self._fetch_new_token()
            self._access_token = token_response['access_token']
            self.logger.info("Successfully obtained new access token")
        else:
            self.logger.debug("Using existing valid token")
        
        return self._access_token

    def _read_token_from_cache(self) -> Optional[str]:
        """
        Read cached access token if still valid.
        
        Returns:
            Optional[str]: Valid cached token or None if not found/expired
        """
        cache_path = os.path.join(self._temp_directory, 'access_token_cache')
        try:
            if os.path.exists(cache_path):
                self.logger.debug("Reading token from cache file: %s", cache_path)
                with open(cache_path, 'r') as file:
                    for line in file.readlines():
                        try:
                            expired_at_time, access_token = line.strip().split(':')
                            if int(expired_at_time) > int(time.time()):
                                self.logger.debug("Found valid token in cache")
                                return access_token
                            else:
                                self.logger.debug("Cached token has expired")
                        except (ValueError, IndexError):
                            self.logger.warning("Invalid cache file format")
            else:
                self.logger.debug("Cache file does not exist")
        except IOError as e:
            self.logger.error("Error reading cache file: %s", e)
        return None

    def _save_token_to_cache(self, access_token: str, expired_at_time: int) -> None:
        """
        Save access token to cache file.
        
        Args:
            access_token: Token to cache
            expired_at_time: Token expiration timestamp
        """
        cache_path = os.path.join(self._temp_directory, 'access_token_cache')
        try:
            self.logger.debug("Saving token to cache file: %s", cache_path)
            with open(cache_path, 'w') as file:
                file.write(f"{expired_at_time}:{access_token}")
            self.logger.debug("Token successfully saved to cache")
        except IOError as e:
            self.logger.error("Error saving token to cache: %s", e)

    def _fetch_new_token(self) -> Dict[str, Any]:
        """
        Fetch new access token from OAuth server.
        
        Performs client credentials OAuth flow to obtain new access token.
        
        Returns:
            Dict[str, Any]: Token response containing:
                {
                    "access_token": str,
                    "expires_in": int,
                    "token_type": "Bearer"
                }
            
        Raises:
            Exception: On authentication errors
        """
        self.logger.debug("Fetching new access token from OAuth server")
        conn = http.client.HTTPSConnection(self._oauth_host)
        try:
            payload = urllib.parse.urlencode({
                'grant_type': 'client_credentials',
                'scope': 'device_full_access'
            })
            auth = base64.b64encode(
                f"{self._client_id}:{self._client_secret}".encode()
            ).decode()
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {auth}'
            }
            
            self.logger.debug("Making OAuth token request")
            conn.request("POST", "/oauth2/token", payload, headers)
            response = conn.getresponse()
            
            if response.status != 200:
                error_body = response.read().decode('utf-8')
                error_msg = "Failed to obtain access token"
                if response.status == 401:
                    error_msg = "Authentication failed - invalid Client ID or Client Secret"
                elif response.status == 403:
                    error_msg = "Authorization failed - insufficient permissions"
                
                self.logger.error("%s: %s", error_msg, error_body)
                raise Exception(error_msg)
            
            response_data = json.loads(response.read().decode('utf-8'))
            
            if 'access_token' in response_data and 'expires_in' in response_data:
                self.logger.debug("Successfully obtained new access token")
                expired_at_time = int(time.time()) + response_data['expires_in']
                self._save_token_to_cache(response_data['access_token'], expired_at_time)
                return response_data
            else:
                error_msg = "Invalid token response format"
                self.logger.error("%s: %s", error_msg, response_data)
                raise Exception(error_msg)
                
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse OAuth response: {e}"
            self.logger.error(error_msg)
            raise Exception(error_msg)
        finally:
            conn.close()

class MetricsCollector:
    """
    Caching metrics collector that updates in the background.
    """
    def __init__(self, client: QingpingClient, update_interval: int = 60):
        """
        Args:
            client: QingpingClient instance
            update_interval: Metrics update interval in seconds
        """
        self.client = client
        self.update_interval = update_interval
        self._metrics_cache = []
        self._cache_lock = threading.Lock()
        self._stop_flag = threading.Event()
        self._collector_thread = None
        self._error_count = 0
        self.logger = logging.getLogger('MetricsCollector')

    def start(self):
        """Start background metrics collector."""
        self._stop_flag.clear()
        self._collector_thread = threading.Thread(target=self._collect_loop)
        self._collector_thread.daemon = True
        self._collector_thread.start()
        self.logger.info("Metrics collector started")

    def stop(self):
        """Stop background metrics collector."""
        self.logger.info("Stopping metrics collector")
        self._stop_flag.set()
        if self._collector_thread:
            self._collector_thread.join()
        self.logger.info("Metrics collector stopped")

    def get_current_metrics(self) -> str:
        """Get current metrics from cache."""
        with self._cache_lock:
            self.logger.debug("Returning %d metrics from cache", len(self._metrics_cache))
            return '\n'.join(self._metrics_cache) + '\n' if self._metrics_cache else "# No metrics available\n"

    def _collect_loop(self):
        """Background metrics collection loop."""
        self.logger.debug("Starting metrics collection loop")
        while not self._stop_flag.is_set():
            try:
                self._update_metrics()
            except Exception as e:
                self.logger.error("Error collecting metrics: %s", e, exc_info=True)
            
            self.logger.debug("Waiting %d seconds until next metrics update", self.update_interval)
            self._stop_flag.wait(self.update_interval)

    def _update_metrics(self):
        """Update metrics cache."""
        try:
            self.logger.debug("Fetching devices data for metrics update")
            response = self.client.get_devices()
            devices = response.get('devices', [])
            self.logger.debug("Processing metrics for %d devices", len(devices))
            
            new_metrics = []
            new_metrics.append("# HELP qingping_error_total Total number of API errors")
            new_metrics.append("# TYPE qingping_error_total counter")
            new_metrics.append(f'qingping_error_total{{type="api_error"}} {self._error_count}')
            
            for device in devices:
                info = device['info']
                data = device['data']
                device_name = info.get('name', 'unknown')
                mac = info.get('mac', 'unknown')
                self.logger.debug("Processing metrics for device: %s (%s)", device_name, mac)

                new_metrics.append("# HELP qingping_device_timestamp_seconds Unix timestamp of last device update")
                new_metrics.append("# TYPE qingping_device_timestamp_seconds gauge")
                timestamp = data.get('timestamp', {}).get('value', None)
                if timestamp is not None:
                    new_metrics.append(
                        f'qingping_device_timestamp_seconds{{device="{device_name}",mac="{mac}"}} {timestamp}'
                    )

                sensors = {
                    'co2': ('ppm', 'CO2 Level'),
                    'pm25': ('ug/m3', 'PM2.5 Level'),
                    'tvoc': ('ppb', 'TVOC Level'),
                    'humidity': ('%', 'Humidity'),
                    'temperature': ('C', 'Temperature')
                }

                new_metrics.append("# HELP qingping_sensor_value Sensor value")
                new_metrics.append("# TYPE qingping_sensor_value gauge")
                for sensor, (unit, desc) in sensors.items():
                    value = data.get(sensor, {}).get('value')
                    if value is not None:
                        self.logger.debug("Device %s: %s = %s %s", device_name, sensor, value, unit)
                        new_metrics.append(
                            f'qingping_sensor_value{{device="{device_name}",mac="{mac}",type="{sensor}",unit="{unit}"}} {value}'
                        )

            with self._cache_lock:
                self.logger.debug("Updating metrics cache with %d new metrics", len(new_metrics))
                self._metrics_cache = new_metrics

        except Exception as e:
            error_type = type(e).__name__
            self._error_count += 1
            self.logger.error("Failed to update metrics (error count: %d): %s", self._error_count, str(e), exc_info=True)
            
            with self._cache_lock:
                self._metrics_cache = [
                    "# HELP qingping_error_total Total number of API errors",
                    "# TYPE qingping_error_total counter",
                    f'qingping_error_total{{type="api_error"}} {self._error_count}'
                ]

class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Custom HTTP handler with proper log formatting"""
    logger = logging.getLogger('HTTPServer')
    
    def log_message(self, format: str, *args: Any) -> None:
        """Override default logging method"""
        self.logger.info("%s - %s", self.address_string(), format % args)

    def log_error(self, format: str, *args: Any) -> None:
        """Override error logging method"""
        self.logger.error("%s - %s", self.address_string(), format % args)

class PrometheusMetricHandler(CustomHTTPRequestHandler):
    """
    HTTP handler for Prometheus metrics and health check.
    """
    collector = None
    health_checker = None

    def do_GET(self):
        if self.path == '/metrics':
            try:
                if not self.collector:
                    raise ValueError("Metrics collector not initialized")
                metrics = self.collector.get_current_metrics()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; version=0.0.4')
                self.end_headers()
                self.wfile.write(metrics.encode('utf-8'))
                self.logger.debug("Metrics request served successfully")
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                error_msg = f"Error serving metrics: {str(e)}"
                self.wfile.write(error_msg.encode('utf-8'))
                self.logger.error(error_msg)
        elif self.path == '/health':
            try:
                if not self.collector or not self.health_checker:
                    raise ValueError("Health checker not initialized")
                
                is_healthy, reason = self.health_checker.check_health()
                
                if is_healthy:
                    self.send_response(200)
                    response = {"status": "healthy", "message": reason}
                else:
                    self.send_response(503)
                    response = {"status": "unhealthy", "message": reason}
                
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                error_msg = f"Error checking health: {str(e)}"
                self.wfile.write(error_msg.encode('utf-8'))
                self.logger.error(error_msg)
        else:
            self.send_response(404)
            self.end_headers()
            self.logger.warning("Request to unknown path: %s", self.path)

class PrometheusExporter:
    def __init__(self, client: QingpingClient, port: int = 9876, update_interval: int = 60,
                 max_errors: int = 6, max_staleness_seconds: int = 3600):
        """
        Initialize Prometheus exporter.
        
        Args:
            client: QingpingClient instance
            port: HTTP server port (default: 9876)
            update_interval: Metrics update interval in seconds
            max_errors: Maximum allowed error count for health check (default: 6)
            max_staleness_seconds: Maximum allowed device timestamp staleness in seconds (default: 3600)
        """
        self.client = client
        self.port = port
        self._max_errors = max_errors
        self._max_staleness_seconds = max_staleness_seconds
        self.server = None
        self.collector = MetricsCollector(client, update_interval)
        self.health_checker = HealthChecker(self.collector, max_errors, max_staleness_seconds)

    @property
    def max_errors(self) -> int:
        """Maximum allowed error count for health check."""
        return self._max_errors

    @max_errors.setter
    def max_errors(self, value: int):
        self._max_errors = value
        if hasattr(self, 'health_checker'):
            self.health_checker.max_errors = value

    @property
    def max_staleness_seconds(self) -> int:
        """Maximum allowed device timestamp staleness in seconds."""
        return self._max_staleness_seconds

    @max_staleness_seconds.setter
    def max_staleness_seconds(self, value: int):
        self._max_staleness_seconds = value
        if hasattr(self, 'health_checker'):
            self.health_checker.max_staleness_seconds = value

    def start(self):
        """Start HTTP server and metrics collector."""
        self.collector.start()

        class Handler(PrometheusMetricHandler):
            pass
        
        Handler.collector = self.collector
        Handler.health_checker = self.health_checker

        self.server = http.server.HTTPServer(('', self.port), Handler)
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print(f"Prometheus exporter started on port {self.port}")

    def stop(self):
        """Stop HTTP server and metrics collector."""
        self.collector.stop()
        if self.server:
            self.server.shutdown()
            self.server.server_close()

class HealthChecker:
    """
    Health checker for monitoring error count and device timestamp staleness.
    """
    def __init__(self, collector: MetricsCollector, max_errors: int = 6, max_staleness_seconds: int = 3600):
        self.collector = collector
        self.max_errors = max_errors
        self.max_staleness_seconds = max_staleness_seconds
        self.logger = logging.getLogger('HealthChecker')
        self.logger.debug("Initialized with max_errors=%d, max_staleness=%d seconds",
                       max_errors, max_staleness_seconds)

    def check_health(self) -> Tuple[bool, str]:
        """
        Check system health based on error count and timestamp staleness.
        
        Returns:
            Tuple[bool, str]: (is_healthy, reason)
        """
        self.logger.debug("Performing health check")
        
        current_errors = self.collector._error_count
        self.logger.debug("Current error count: %d (max allowed: %d)", 
                       current_errors, self.max_errors)
        
        if current_errors >= self.max_errors:
            error_msg = f"Error count ({current_errors}) exceeded threshold ({self.max_errors})"
            self.logger.warning(error_msg)
            return False, error_msg

        self.logger.debug("Checking device timestamp staleness")
        with self.collector._cache_lock:
            for metric in self.collector._metrics_cache:
                if 'qingping_device_timestamp_seconds{' in metric:
                    try:
                        timestamp = float(metric.split('}')[-1].strip())
                        staleness = time.time() - timestamp
                        self.logger.debug("Device timestamp staleness: %.1f seconds (max allowed: %d)",
                                      staleness, self.max_staleness_seconds)
                        
                        if staleness > self.max_staleness_seconds:
                            error_msg = f"Device timestamp is stale ({int(staleness)}s > {self.max_staleness_seconds}s)"
                            self.logger.warning(error_msg)
                            return False, error_msg
                    except (ValueError, IndexError) as e:
                        self.logger.error("Failed to parse timestamp from metric: %s", metric, exc_info=True)
                        continue

        self.logger.debug("Health check passed successfully")
        return True, "OK"

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Setup application-wide logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If not provided, logs will go to stdout only
    """
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    root_logger.setLevel(log_level)
    
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def get_config() -> Tuple[str, str, int, int, int, int, str, Optional[str]]:
    """
    Get configuration from command line arguments and environment variables.
    Command line arguments take precedence.
    
    Returns:
        Tuple[str, str, int, int, int, int, str, Optional[str]]: client_id, client_secret, port, 
                                                                update_interval, max_errors, 
                                                                max_staleness_seconds, log_level,
                                                                log_file
    """
    parser = argparse.ArgumentParser(description='Qingping Prometheus Exporter')
    parser.add_argument('--client-id', help='OAuth client ID')
    parser.add_argument('--client-secret', help='OAuth client secret')
    parser.add_argument('--port', type=int, help='HTTP server port (default: 9876)')
    parser.add_argument('--interval', type=int, help='Metrics update interval in seconds (default: 60)')
    parser.add_argument('--max-errors', type=int, help='Maximum allowed error count for health check (default: 6)')
    parser.add_argument('--max-staleness', type=int, help='Maximum allowed device timestamp staleness in seconds (default: 3600)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      help='Set the logging level (default: INFO)')
    parser.add_argument('--log-file', help='Path to log file (optional)')
    
    args = parser.parse_args()
    
    client_id = args.client_id or os.environ.get('QINGPING_CLIENT_ID')
    client_secret = args.client_secret or os.environ.get('QINGPING_CLIENT_SECRET')
    
    try:
        port = args.port or int(os.environ.get('HTTP_EXPORTER_PORT', '9876'))
    except ValueError:
        port = 9876
        
    try:
        interval = args.interval or int(os.environ.get('QINGPING_UPDATE_INTERVAL', '60'))
    except ValueError:
        interval = 60
    
    try:
        max_errors = args.max_errors or int(os.environ.get('QINGPING_MAX_ERRORS', '6'))
    except ValueError:
        max_errors = 6
        
    try:
        max_staleness = args.max_staleness or int(os.environ.get('QINGPING_MAX_STALENESS_SECONDS', '3600'))
    except ValueError:
        max_staleness = 3600
    
    log_level = args.log_level or os.environ.get('LOG_LEVEL', 'INFO')
    log_file = args.log_file or os.environ.get('LOG_FILE')
    
    if not client_id or not client_secret:
        raise ValueError(
            "Client ID and Client Secret are required. "
            "Provide them via command line arguments (--client-id, --client-secret) "
            "or environment variables (QINGPING_CLIENT_ID, QINGPING_CLIENT_SECRET)"
        )
    
    return client_id, client_secret, port, interval, max_errors, max_staleness, log_level, log_file

if __name__ == "__main__":
    # Initialize basic logging first for early error handling
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO
    )
    logger = logging.getLogger(__name__)

    try:
        config = get_config()
        client_id, client_secret, port, interval, max_errors, max_staleness, log_level, log_file = config
        
        # Now setup proper logging with all configurations
        setup_logging(log_level, log_file)
        
        logger.info("Initializing Qingping Prometheus Exporter")
        logger.debug("Configuration: port=%d, interval=%d, max_errors=%d, max_staleness=%d, log_level=%s, log_file=%s",
                   port, interval, max_errors, max_staleness, log_level, log_file or "stdout")
        
        client = QingpingClient(
            client_id=client_id,
            client_secret=client_secret,
            temp_directory="temp"
        )
        
        exporter = PrometheusExporter(
            client=client,
            port=port,
            update_interval=interval,
            max_errors=max_errors,
            max_staleness_seconds=max_staleness
        )
        
        logger.info("Starting Qingping Prometheus Exporter on port %d", port)
        logger.info("Update interval: %d seconds", interval)
        logger.info("Maximum errors allowed: %d", max_errors)
        logger.info("Maximum staleness: %d seconds", max_staleness)
        
        exporter.start()
        logger.info("Exporter started successfully")
        
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down exporter...")
        exporter.stop()
    except ValueError as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        sys.exit(1)
    