import http.client
import urllib.parse
import os
import base64
import json
import time
import logging
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
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self._temp_directory):
            os.makedirs(self._temp_directory)

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
        return self._make_api_request("GET", "/v1/apis/devices")

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
        
        conn = http.client.HTTPSConnection(self._api_host)
        try:
            headers = {
                'Authorization': f"Bearer {access_token}",
                'Content-Type': 'application/json'
            }
            
            if payload:
                body = json.dumps(payload)
            else:
                body = None
                
            conn.request(method, path, body, headers)
            return self._handle_response(conn.getresponse())
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
            if not content_type:  # Empty response
                return {}
                
            if not content_type.startswith('application/json'):
                raise Exception(f"Unexpected Content-Type: {content_type}")
                
            data = response.read()
            try:
                return json.loads(data.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise Exception(f"Failed to decode JSON response: {e}")
        elif response.status == 401:
            # Token expired, reset and retry
            self._access_token = None
            return self.get_devices()
        else:
            raise Exception(f"API request failed. Status: {response.status}")

    def _ensure_valid_token(self) -> str:
        """
        Ensure a valid access token is available.
        
        Checks cache for valid token, fetches new one if needed.
        
        Returns:
            str: Valid access token
        """
        if not self._access_token:
            self._access_token = self._read_token_from_cache()
        
        if not self._access_token:
            token_response = self._fetch_new_token()
            self._access_token = token_response['access_token']
        
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
                with open(cache_path, 'r') as file:
                    for line in file.readlines():
                        try:
                            expired_at_time, access_token = line.strip().split(':')
                            if int(expired_at_time) > int(time.time()):
                                return access_token
                        except (ValueError, IndexError):
                            logging.warning("Invalid cache file format")
        except IOError as e:
            logging.error(f"Error reading cache file: {e}")
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
            with open(cache_path, 'w') as file:
                file.write(f"{expired_at_time}:{access_token}")
        except IOError as e:
            logging.error(f"Error saving token to cache: {e}")

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
            
            conn.request("POST", "/oauth2/token", payload, headers)
            response = self._handle_response(conn.getresponse())
            
            if 'access_token' in response and 'expires_in' in response:
                expired_at_time = int(time.time()) + response['expires_in']
                self._save_token_to_cache(response['access_token'], expired_at_time)
                return response
            else:
                raise Exception("Invalid token response format")
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

    def start(self):
        """Start background metrics collector."""
        self._stop_flag.clear()
        self._collector_thread = threading.Thread(target=self._collect_loop)
        self._collector_thread.daemon = True
        self._collector_thread.start()

    def stop(self):
        """Stop background metrics collector."""
        self._stop_flag.set()
        if self._collector_thread:
            self._collector_thread.join()

    def get_current_metrics(self) -> str:
        """Get current metrics from cache."""
        with self._cache_lock:
            return '\n'.join(self._metrics_cache) + '\n' if self._metrics_cache else "# No metrics available\n"

    def _collect_loop(self):
        """Background metrics collection loop."""
        while not self._stop_flag.is_set():
            try:
                self._update_metrics()
            except Exception as e:
                logging.error(f"Error collecting metrics: {e}")
            
            # Wait for next update or stop signal
            self._stop_flag.wait(self.update_interval)

    def _update_metrics(self):
        """Update metrics cache."""
        try:
            response = self.client.get_devices()
            devices = response.get('devices', [])
            
            new_metrics = []
            new_metrics.append("# HELP qingping_sensor_value Sensor value")
            new_metrics.append("# TYPE qingping_sensor_value gauge")
            
            for device in devices:
                info = device['info']
                data = device['data']
                device_name = info.get('name', 'unknown')
                mac = info.get('mac', 'unknown')

                sensors = {
                    'co2': ('ppm', 'CO2 Level'),
                    'pm25': ('ug/m3', 'PM2.5 Level'),
                    'tvoc': ('ppb', 'TVOC Level'),
                    'humidity': ('%', 'Humidity'),
                    'temperature': ('C', 'Temperature')
                }

                for sensor, (unit, desc) in sensors.items():
                    value = data.get(sensor, {}).get('value')
                    if value is not None:
                        new_metrics.append(
                            f'qingping_sensor_value{{device="{device_name}",mac="{mac}",type="{sensor}",unit="{unit}"}} {value}'
                        )

            # Atomic cache update
            with self._cache_lock:
                self._metrics_cache = new_metrics

        except Exception as e:
            with self._cache_lock:
                self._metrics_cache = [f"# Error collecting metrics: {str(e)}"]

class PrometheusMetricHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for Prometheus metrics.
    """
    collector = None  # Static class attribute

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
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Error serving metrics: {str(e)}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

class PrometheusExporter:
    def __init__(self, client: QingpingClient, port: int = 9876, update_interval: int = 60):
        """
        Initialize Prometheus exporter.
        
        Args:
            client: QingpingClient instance
            port: HTTP server port (default: 9876)
            update_interval: Metrics update interval in seconds
        """
        self.client = client
        self.port = port
        self.server = None
        self.collector = MetricsCollector(client, update_interval)

    def start(self):
        """Start HTTP server and metrics collector."""
        self.collector.start()

        # Create handler subclass with collector set
        class Handler(PrometheusMetricHandler):
            pass
        
        # Set collector as static class attribute
        Handler.collector = self.collector

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

def get_config() -> Tuple[str, str, int, int]:
    """
    Get configuration from command line arguments and environment variables.
    Command line arguments take precedence.
    
    Returns:
        Tuple[str, str, int, int]: client_id, client_secret, port, update_interval
    
    Raises:
        ValueError: If required parameters are missing
    """
    parser = argparse.ArgumentParser(description='Qingping Prometheus Exporter')
    parser.add_argument('--client-id', help='OAuth client ID')
    parser.add_argument('--client-secret', help='OAuth client secret')
    parser.add_argument('--port', type=int, help='HTTP server port (default: 9876)')
    parser.add_argument('--interval', type=int, help='Metrics update interval in seconds (default: 60)')
    
    args = parser.parse_args()
    
    # Get values from arguments or environment variables
    client_id = args.client_id or os.environ.get('QINGPING_CLIENT_ID')
    client_secret = args.client_secret or os.environ.get('QINGPING_CLIENT_SECRET')
    
    # For port and interval, check arguments first, then environment variables,
    # then use default values
    try:
        port = args.port or int(os.environ.get('HTTP_EXPORTER_PORT', '9876'))
    except ValueError:
        port = 9876
        
    try:
        interval = args.interval or int(os.environ.get('QINGPING_UPDATE_INTERVAL', '60'))
    except ValueError:
        interval = 60
    
    if not client_id or not client_secret:
        raise ValueError(
            "Client ID and Client Secret are required. "
            "Provide them via command line arguments (--client-id, --client-secret) "
            "or environment variables (QINGPING_CLIENT_ID, QINGPING_CLIENT_SECRET)"
        )
    
    return client_id, client_secret, port, interval

if __name__ == "__main__":
    try:
        client_id, client_secret, port, interval = get_config()
        
        client = QingpingClient(
            client_id=client_id,
            client_secret=client_secret,
            temp_directory="temp"
        )
        
        exporter = PrometheusExporter(
            client=client,
            port=port,
            update_interval=interval
        )
        
        print(f"Starting Qingping Prometheus Exporter:")
        print(f"Port: {port}")
        print(f"Update interval: {interval} seconds")
        
        exporter.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down exporter...")
        exporter.stop()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
