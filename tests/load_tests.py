"""
Load and performance tests for CyberGuard system

This module tests system performance under various loads:
1. High request volume
2. Concurrent user simulation
3. Memory usage under load
4. CPU utilization
5. Response time degradation
6. Throughput measurements
7. Scalability testing
8. Stress testing beyond normal limits

Each test measures performance metrics and ensures system stability.
"""

import pytest
import sys
import os
import time
import threading
import concurrent.futures
import asyncio
import random
import statistics
import json  # Added missing import
import psutil  # Added missing import
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import test utilities
from tests.test_utils import (
    create_mock_threat_data,
    create_mock_website_data,
    TEST_CONFIG
)

# Test markers
pytestmark = [
    pytest.mark.performance,
    pytest.mark.load,
    pytest.mark.slow,
    pytest.mark.integration
]

class TestConcurrentRequests:
    """Tests for handling concurrent requests"""
    
    def test_single_agent_concurrent_requests(self, threat_detection_agent):
        """Test single agent handling concurrent requests"""
        # Arrange: Setup test environment with agent and request parameters
        agent = threat_detection_agent
        num_concurrent = 10  # Number of concurrent requests to simulate
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',  # XSS payload for testing
            'headers': {},  # Empty headers for simplicity
            'body': '',  # No body for GET request
            'method': 'GET'  # HTTP method
        }
        
        results = []  # Store successful results
        errors = []   # Store error results
        
        # Define worker function for concurrent execution
        def analyze_request(request_id: int):
            try:
                start_time = time.time()  # Record start time for performance measurement
                result = agent.analyze(request_data)  # Execute threat analysis
                end_time = time.time()  # Record end time
                
                # Return success result with metrics
                return {
                    'request_id': request_id,
                    'success': True,
                    'response_time': end_time - start_time,  # Calculate response time
                    'threat_level': result['threat_level']  # Extract threat detection result
                }
            except Exception as e:
                # Return error result if analysis fails
                return {
                    'request_id': request_id,
                    'success': False,
                    'error': str(e)  # Capture error message
                }
        
        # Act: Execute concurrent requests using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all requests to executor, mapping futures to request IDs
            future_to_id = {
                executor.submit(analyze_request, i): i
                for i in range(num_concurrent)
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_id):
                result = future.result()  # Get result from completed future
                if result['success']:
                    results.append(result)  # Store success
                else:
                    errors.append(result)  # Store error
        
        # Assert: Validate test results
        assert len(errors) == 0, f"Should handle concurrent requests without errors: {errors}"
        assert len(results) == num_concurrent, f"Should process all requests: {len(results)}/{num_concurrent}"
        
        # Calculate performance statistics
        response_times = [r['response_time'] for r in results]
        avg_response_time = statistics.mean(response_times)  # Average response time
        max_response_time = max(response_times)  # Maximum response time
        
        # Response times should be reasonable (performance requirements)
        assert avg_response_time < 0.5, f"Average response time too high: {avg_response_time:.3f}s"
        assert max_response_time < 1.0, f"Maximum response time too high: {max_response_time:.3f}s"
        
        # All requests should detect threat (XSS payload)
        threat_levels = [r['threat_level'] for r in results]
        assert all(tl > 0.5 for tl in threat_levels), \
            f"All requests should detect threat, got min={min(threat_levels):.3f}"
        
        # Print test summary for monitoring
        print(f"Concurrent requests ({num_concurrent}): "
              f"avg_time={avg_response_time:.3f}s, "
              f"max_time={max_response_time:.3f}s, "
              f"success_rate={len(results)/num_concurrent*100:.1f}%")
    
    def test_multi_agent_concurrent_coordination(self, agent_orchestrator):
        """Test multi-agent coordination under concurrent load"""
        # Arrange: Setup orchestrator and mixed request types
        orchestrator = agent_orchestrator
        num_concurrent = 5  # Number of concurrent coordination requests
        
        # Different types of requests to simulate varied workload
        request_types = [
            {
                'name': 'xss_attack',  # Cross-site scripting attack
                'data': {
                    'url': 'https://test.com/?q=<script>alert(1)</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'sqli_attack',  # SQL injection attack
                'data': {
                    'url': 'https://test.com/login?user=admin&pass=%27OR%271%27%3D%271',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'normal_traffic',  # Normal benign traffic
                'data': {
                    'url': 'https://test.com/about',
                    'headers': {'User-Agent': 'Mozilla/5.0'},
                    'body': '',
                    'method': 'GET'
                }
            }
        ]
        
        results = []  # Store successful coordination results
        errors = []   # Store coordination errors
        
        # Define worker function for concurrent coordination
        def coordinate_analysis(request_type: Dict, request_id: int):
            try:
                start_time = time.time()  # Start timing
                result = orchestrator.coordinate_analysis(request_type['data'])  # Coordinate analysis
                end_time = time.time()  # End timing
                
                # Return success result
                return {
                    'request_id': request_id,
                    'type': request_type['name'],
                    'success': True,
                    'response_time': end_time - start_time,
                    'threat_level': result['final_decision']['threat_level']
                }
            except Exception as e:
                # Return error result
                return {
                    'request_id': request_id,
                    'type': request_type['name'],
                    'success': False,
                    'error': str(e)
                }
        
        # Create mixed workload by randomly selecting request types
        workload = []
        for i in range(num_concurrent):
            request_type = random.choice(request_types)  # Randomly select request type
            workload.append((request_type, i))  # Add to workload with ID
        
        # Act: Execute concurrent coordination
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all coordination requests
            future_to_req = {
                executor.submit(coordinate_analysis, req_type, req_id): (req_type, req_id)
                for req_type, req_id in workload
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_req):
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
        
        # Assert: Validate coordination results
        assert len(errors) == 0, f"Should handle concurrent coordination: {errors}"
        
        # Calculate performance statistics if we have results
        if results:
            response_times = [r['response_time'] for r in results]
            avg_response_time = statistics.mean(response_times)  # Average coordination time
            max_response_time = max(response_times)  # Maximum coordination time
            
            # Coordination takes more time than single agent but should be reasonable
            assert avg_response_time < 2.0, f"Average coordination time too high: {avg_response_time:.3f}s"
            
            # Print coordination performance summary
            print(f"Multi-agent concurrent coordination ({num_concurrent}): "
                  f"avg_time={avg_response_time:.3f}s, "
                  f"max_time={max_response_time:.3f}s")

class TestHighVolumeLoad:
    """Tests for high volume request handling"""
    
    def test_high_volume_requests(self, threat_detection_agent):
        """Test handling high volume of requests"""
        # Arrange: Setup for high volume test
        agent = threat_detection_agent
        num_requests = 100  # High volume test count
        
        # Generate variety of requests (malicious and benign mix)
        requests = []
        for i in range(num_requests):
            # Mix of malicious and benign requests
            if i % 4 == 0:  # 25% malicious - XSS
                payload = '<script>alert("XSS")</script>'
            elif i % 4 == 1:  # 25% malicious - SQLi
                payload = "' OR '1'='1"
            else:  # 50% benign
                payload = f'legitimate_query_{i}'
            
            # Create request with payload
            requests.append({
                'url': f'https://test.com/?q={payload}',
                'headers': {},
                'body': '',
                'method': 'GET'
            })
        
        response_times = []  # Store individual response times
        threat_levels = []   # Store threat detection results
        
        # Act: Process high volume sequentially
        start_total = time.time()  # Start total timer
        
        for i, request in enumerate(requests):
            request_start = time.time()  # Start per-request timer
            result = agent.analyze(request)  # Analyze request
            request_end = time.time()  # End per-request timer
            
            response_times.append(request_end - request_start)  # Store response time
            threat_levels.append(result['threat_level'])  # Store threat level
            
            # Progress indicator for large tests
            if (i + 1) % 20 == 0:
                print(f"  Processed {i + 1}/{num_requests} requests")
        
        end_total = time.time()  # End total timer
        total_time = end_total - start_total  # Calculate total processing time
        
        # Assert: Validate high volume processing
        # No crashes during high volume processing
        assert len(response_times) == num_requests, \
            f"Should process all {num_requests} requests"
        
        # Calculate throughput (requests per second)
        throughput = num_requests / total_time
        
        # Calculate performance metrics
        avg_response_time = statistics.mean(response_times)  # Average response time
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile response time
        
        # Print test summary
        print(f"\nHigh Volume Test ({num_requests} requests):")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {throughput:.1f} requests/second")
        print(f"  Avg response time: {avg_response_time:.3f}s")
        print(f"  95th percentile: {p95_response_time:.3f}s")
        
        # Should maintain reasonable throughput
        assert throughput > 10, f"Throughput too low: {throughput:.1f} requests/second"
        
        # Response time should not degrade excessively (p95 < 3x avg)
        assert p95_response_time < avg_response_time * 3, \
            f"Response time degradation too high: p95={p95_response_time:.3f}s, avg={avg_response_time:.3f}s"
    
    def test_sustained_load(self, threat_detection_agent):
        """Test sustained load over time"""
        # Arrange: Setup for sustained load test
        agent = threat_detection_agent
        duration = 30  # Test duration in seconds
        requests_per_second = 5  # Target request rate
        
        total_requests = duration * requests_per_second  # Expected total requests
        request_count = 0  # Actual request counter
        response_times = []  # Response time storage
        
        # Create request template (same request repeated)
        request_template = {
            'url': 'https://test.com/?q=test',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act: Sustained load simulation
        start_time = time.time()  # Test start time
        end_time = start_time + duration  # Test end time
        
        print(f"Starting sustained load test: {duration}s at {requests_per_second} req/s")
        
        # Run for specified duration
        while time.time() < end_time:
            batch_start = time.time()  # Batch start time
            
            # Process batch of requests at target rate
            for _ in range(requests_per_second):
                request_start = time.time()  # Per-request start
                result = agent.analyze(request_template)  # Analyze request
                request_end = time.time()  # Per-request end
                
                response_times.append(request_end - request_start)  # Store response time
                request_count += 1  # Increment counter
            
            batch_end = time.time()  # Batch end time
            batch_time = batch_end - batch_start  # Batch processing time
            
            # Throttle to maintain target rate (if batch completed too quickly)
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
        
        total_time = time.time() - start_time  # Actual total time
        actual_rate = request_count / total_time  # Actual achieved rate
        
        # Assert: Validate sustained load performance
        print(f"\nSustained Load Test:")
        print(f"  Target: {requests_per_second} req/s for {duration}s")
        print(f"  Actual: {actual_rate:.1f} req/s for {total_time:.1f}s")
        print(f"  Total requests: {request_count}")
        
        if response_times:
            avg_response = statistics.mean(response_times)  # Average response time
            max_response = max(response_times)  # Maximum response time
            
            print(f"  Avg response time: {avg_response:.3f}s")
            print(f"  Max response time: {max_response:.3f}s")
            
            # Should maintain stable performance (no excessive spikes)
            assert max_response < avg_response * 5, \
                f"Response time spikes too high: max={max_response:.3f}s, avg={avg_response:.3f}s"
            
            # Should achieve target rate (±20% tolerance)
            assert abs(actual_rate - requests_per_second) / requests_per_second < 0.2, \
                f"Rate deviation too high: target={requests_per_second}, actual={actual_rate:.1f}"

class TestMemoryUsage:
    """Tests for memory usage under load"""
    
    def test_memory_usage_single_agent(self, threat_detection_agent):
        """Test memory usage of single agent"""
        # Arrange: Setup memory monitoring
        agent = threat_detection_agent
        num_requests = 50  # Number of requests for memory test
        
        # Track memory usage using psutil
        process = psutil.Process(os.getpid())  # Get current process
        initial_memory = process.memory_info().rss / 1024 / 1024  # Initial memory in MB
        
        # Act: Process requests while monitoring memory
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Process multiple requests to observe memory patterns
        for i in range(num_requests):
            result = agent.analyze(request_data)
            assert result['threat_level'] > 0.5, "Should detect threat"
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # Final memory in MB
        memory_increase = final_memory - initial_memory  # Memory increase
        
        # Assert: Validate memory usage
        print(f"\nMemory Usage Test (Single Agent):")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory increase: {memory_increase:.1f} MB")
        print(f"  Requests processed: {num_requests}")
        
        # Memory increase should be reasonable (no memory leak)
        # Allow some increase for caching/optimization but limit to 50MB
        assert memory_increase < 50, f"Memory leak suspected: increased by {memory_increase:.1f} MB"
        
        # Memory per request should be low (efficient memory usage)
        memory_per_request = memory_increase / num_requests
        assert memory_per_request < 0.5, f"Memory per request too high: {memory_per_request:.2f} MB/request"
    
    def test_memory_usage_multi_agent(self, agent_orchestrator):
        """Test memory usage with multi-agent coordination"""
        # Arrange: Setup for multi-agent memory test
        orchestrator = agent_orchestrator
        num_requests = 30  # Fewer requests due to higher memory overhead
        
        # Track memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # Initial memory in MB
        
        # Act: Process coordinated requests
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Process requests through orchestrator (more memory intensive)
        for i in range(num_requests):
            result = orchestrator.coordinate_analysis(request_data)
            assert result['final_decision']['threat_level'] > 0.5, "Should detect threat"
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # Final memory in MB
        memory_increase = final_memory - initial_memory  # Memory increase
        
        # Assert: Validate multi-agent memory usage
        print(f"\nMemory Usage Test (Multi-Agent):")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory increase: {memory_increase:.1f} MB")
        print(f"  Requests processed: {num_requests}")
        
        # Multi-agent uses more memory but should still be reasonable
        # Higher threshold due to coordination overhead
        assert memory_increase < 100, f"Memory leak suspected: increased by {memory_increase:.1f} MB"

class TestScalability:
    """Tests for system scalability"""
    
    def test_scaling_with_request_complexity(self, threat_detection_agent):
        """Test how performance scales with request complexity"""
        # Arrange: Define requests with increasing complexity
        agent = threat_detection_agent
        
        # Requests of increasing complexity
        complexity_levels = [
            {
                'name': 'simple',  # Simple request
                'data': {
                    'url': 'https://test.com/',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'medium',  # Medium complexity with query params
                'data': {
                    'url': 'https://test.com/?q=test&user=admin&session=abc123',
                    'headers': {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'complex',  # Complex request with XSS and many headers
                'data': {
                    'url': 'https://test.com/search?q=<script>alert(1)</script>&filter=all&sort=date',
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive'
                    },
                    'body': 'additional=data&more=parameters',
                    'method': 'POST'
                }
            }
        ]
        
        results = []  # Store complexity test results
        
        # Act: Measure performance at each complexity level
        for level in complexity_levels:
            response_times = []  # Store response times for this complexity level
            
            # Run multiple times for statistical significance
            for _ in range(10):
                start_time = time.time()
                result = agent.analyze(level['data'])  # Analyze at current complexity
                end_time = time.time()
                
                response_times.append(end_time - start_time)  # Store response time
            
            # Calculate statistics for this complexity level
            avg_time = statistics.mean(response_times)  # Average response time
            std_time = statistics.stdev(response_times) if len(response_times) > 1 else 0  # Standard deviation
            
            results.append({
                'level': level['name'],
                'avg_time': avg_time,
                'std_time': std_time
            })
        
        # Assert: Validate scalability characteristics
        print(f"\nScalability with Complexity:")
        for result in results:
            print(f"  {result['level']}: avg={result['avg_time']:.3f}s ±{result['std_time']:.3f}s")
        
        # Complex requests should take longer but not exponentially
        simple_time = results[0]['avg_time']  # Simple request time
        complex_time = results[-1]['avg_time']  # Complex request time
        
        complexity_ratio = complex_time / simple_time  # How much slower complex is
        
        # Complex requests should not be exponentially slower (limit 10x)
        assert complexity_ratio < 10, \
            f"Complexity scaling too high: simple={simple_time:.3f}s, complex={complex_time:.3f}s, ratio={complexity_ratio:.1f}"
        
        # Variation should be reasonable (std < 50% of avg)
        for result in results:
            assert result['std_time'] < result['avg_time'] * 0.5, \
                f"Response time too variable for {result['level']}: std={result['std_time']:.3f}s"
    
    def test_agent_count_scalability(self):
        """Test how performance scales with number of agents"""
        # Note: This test would create multiple agent instances
        # and measure coordination overhead
        
        # Skip this test as it requires dynamic agent creation infrastructure
        pytest.skip("Agent count scalability test requires dynamic agent creation")
        # Implementation would create orchestrators with different agent counts
        # and measure coordination time

class TestStressTesting:
    """Stress tests beyond normal limits"""
    
    def test_extreme_concurrency(self, threat_detection_agent):
        """Test extreme concurrency levels"""
        # Arrange: Setup for extreme concurrency test
        agent = threat_detection_agent
        num_concurrent = 50  # Extreme concurrency level
        
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        results = []  # Store successful results
        errors = []   # Store error results
        
        # Define worker function for extreme concurrency
        def analyze_request(request_id: int):
            try:
                start_time = time.time()
                result = agent.analyze(request_data)
                end_time = time.time()
                
                return {
                    'request_id': request_id,
                    'success': True,
                    'response_time': end_time - start_time,
                    'threat_level': result['threat_level']
                }
            except Exception as e:
                return {
                    'request_id': request_id,
                    'success': False,
                    'error': str(e)
                }
        
        # Act: Execute extreme concurrency test
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all requests (extreme load)
            future_to_id = {
                executor.submit(analyze_request, i): i
                for i in range(num_concurrent)
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_id):
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
        
        # Assert: Validate extreme concurrency handling
        success_rate = len(results) / num_concurrent  # Calculate success rate
        
        print(f"\nExtreme Concurrency Test ({num_concurrent} concurrent):")
        print(f"  Success rate: {success_rate*100:.1f}%")
        print(f"  Errors: {len(errors)}")
        
        # Show first few errors if any
        if errors:
            for error in errors[:3]:  # Limit to first 3 errors
                print(f"    Error in request {error['request_id']}: {error['error'][:100]}...")
        
        # Should handle most requests even under extreme load (80% success minimum)
        assert success_rate > 0.8, f"Success rate too low under extreme concurrency: {success_rate*100:.1f}%"
        
        # Calculate and print performance metrics if we have results
        if results:
            response_times = [r['response_time'] for r in results]
            avg_time = statistics.mean(response_times)
            max_time = max(response_times)
            
            print(f"  Avg response time: {avg_time:.3f}s")
            print(f"  Max response time: {max_time:.3f}s")
    
    def test_very_large_payloads(self, threat_detection_agent):
        """Test handling of very large request payloads"""
        # Arrange: Setup large payload tests
        agent = threat_detection_agent
        
        # Generate large payloads of different types
        large_payloads = [
            {
                'name': 'large_json',  # Large JSON payload
                'data': {
                    'url': 'https://api.test.com/data',
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'data': 'A' * 10000}),  # 10KB JSON payload
                    'method': 'POST'
                }
            },
            {
                'name': 'large_form',  # Large form data
                'data': {
                    'url': 'https://test.com/upload',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'body': '&'.join([f'field{i}=value{"B"*100}' for i in range(100)]),  # ~10KB form data
                    'method': 'POST'
                }
            },
            {
                'name': 'large_xss',  # Large XSS payload
                'data': {
                    'url': 'https://test.com/?q=' + '<script>' + 'alert("X");' * 1000 + '</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            }
        ]
        
        # Act & Assert: Test each large payload type
        for payload_test in large_payloads:
            start_time = time.time()  # Start timing
            
            try:
                result = agent.analyze(payload_test['data'])  # Analyze large payload
                end_time = time.time()  # End timing
                
                response_time = end_time - start_time  # Calculate response time
                
                # Assert: Should handle large payloads within time limit
                assert response_time < 5.0, \
                    f"{payload_test['name']}: Response time too high for large payload: {response_time:.2f}s"
                
                # Should not crash and return proper result
                assert 'threat_level' in result, \
                    f"{payload_test['name']}: Should return result with threat_level"
                
                # Print success message
                print(f"  {payload_test['name']}: handled in {response_time:.2f}s, threat={result['threat_level']:.2f}")
                
            except Exception as e:
                # Fail test if large payload causes crash
                pytest.fail(f"{payload_test['name']}: Failed to handle large payload: {e}")

class TestPerformanceMonitoring:
    """Tests for performance monitoring and metrics"""
    
    def test_performance_metrics_collection(self, agent_orchestrator):
        """Test collection of performance metrics"""
        # Arrange: Setup for metrics collection test
        orchestrator = agent_orchestrator
        
        # Process some requests to generate metrics data
        requests = [
            {
                'url': 'https://test.com/?q=<script>alert(1)</script>',  # Malicious request
                'headers': {},
                'body': '',
                'method': 'GET'
            },
            {
                'url': 'https://test.com/about',  # Benign request
                'headers': {},
                'body': '',
                'method': 'GET'
            }
        ]
        
        # Generate activity for metrics
        for request in requests:
            orchestrator.coordinate_analysis(request)
        
        # Act: Get system status/metrics
        # Try to get system status if method exists
        try:
            status = orchestrator.get_system_status()
        except AttributeError:
            # Skip test if system status method not available
            pytest.skip("System status method not available")
        
        # Assert: Validate metrics collection
        assert 'metrics' in status, "System status should contain metrics"
        
        metrics = status['metrics']  # Extract metrics
        
        # Check expected metrics are present
        expected_metrics = ['total_analyses', 'threats_detected']
        for metric in expected_metrics:
            assert metric in metrics, f"Should contain {metric} metric"
        
        # Metrics should be numeric values
        assert isinstance(metrics['total_analyses'], (int, float)), \
            "total_analyses should be numeric"
        
        # Print metrics for monitoring/debugging
        print(f"\nPerformance Metrics:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
        # Should have processed our test requests
        assert metrics['total_analyses'] >= len(requests), \
            f"Should track total analyses: {metrics['total_analyses']} >= {len(requests)}"
    
    def test_response_time_tracking(self, threat_detection_agent):
        """Test tracking of response time percentiles"""
        # Arrange: Setup for percentile tracking test
        agent = threat_detection_agent
        num_requests = 100  # Number of requests for percentile calculation
        
        request_data = {
            'url': 'https://test.com/?q=test',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        response_times = []  # Store all response times
        
        # Act: Collect response times with variability
        for i in range(num_requests):
            start_time = time.time()
            result = agent.analyze(request_data)
            end_time = time.time()
            
            response_times.append(end_time - start_time)  # Store response time
            
            # Add small random delay to create realistic variability
            time.sleep(random.uniform(0.001, 0.01))
        
        # Calculate percentiles from sorted response times
        response_times.sort()  # Sort for percentile calculation
        
        percentiles = {
            'p50': response_times[int(num_requests * 0.5)],  # 50th percentile (median)
            'p90': response_times[int(num_requests * 0.9)],  # 90th percentile
            'p95': response_times[int(num_requests * 0.95)],  # 95th percentile
            'p99': response_times[int(num_requests * 0.99)],  # 99th percentile
        }
        
        # Assert: Validate percentile characteristics
        print(f"\nResponse Time Percentiles ({num_requests} requests):")
        for percentile, value in percentiles.items():
            print(f"  {percentile}: {value:.3f}s")
        
        # p99 should not be too much worse than p50 (no extreme outliers)
        p99_to_p50_ratio = percentiles['p99'] / percentiles['p50']
        assert p99_to_p50_ratio < 5, \
            f"p99 too high relative to p50: ratio={p99_to_p50_ratio:.1f}"
        
        # All percentiles should be within reasonable bounds (1 second maximum)
        max_allowed = 1.0
        for percentile, value in percentiles.items():
            assert value < max_allowed, \
                f"{percentile} response time too high: {value:.3f}s > {max_allowed}s"

@pytest.mark.integration
class TestEndToEndLoad:
    """End-to-end load testing"""
    
    def test_complete_system_load(self, agent_orchestrator):
        """Test complete system under mixed load"""
        # Arrange: Setup for end-to-end load test
        orchestrator = agent_orchestrator
        num_requests = 50  # Total requests for mixed workload
        
        # Create mixed workload with different request types
        workload = []
        for i in range(num_requests):
            # Distribute request types: 20% XSS, 20% SQLi, 60% normal
            if i % 5 == 0:  # 20% XSS attacks
                workload.append({
                    'url': f'https://test.com/?q=<script>alert({i})</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                })
            elif i % 5 == 1:  # 20% SQL injection attacks
                workload.append({
                    'url': f'https://test.com/login?user=admin&pass=%27OR%27{i}%27%3D%27{i}',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                })
            else:  # 60% normal traffic
                workload.append({
                    'url': f'https://test.com/page{i}',
                    'headers': {'User-Agent': 'Mozilla/5.0'},
                    'body': '',
                    'method': 'GET'
                })
        
        results = []  # Store test results
        start_time = time.time()  # Start total timer
        
        # Act: Process mixed workload through complete system
        for i, request in enumerate(workload):
            request_start = time.time()  # Per-request start
            
            result = orchestrator.coordinate_analysis(request)  # Full system analysis
            
            request_end = time.time()  # Per-request end
            
            # Store comprehensive results
            results.append({
                'request_id': i,
                'response_time': request_end - request_start,
                'threat_level': result['final_decision']['threat_level'],
                'action': result['final_decision']['action']
            })
            
            # Progress indicator
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{num_requests} requests")
        
        end_time = time.time()  # End total timer
        total_time = end_time - start_time  # Total processing time
        
        # Assert: Validate complete system performance
        print(f"\nComplete System Load Test:")
        print(f"  Total requests: {num_requests}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Overall throughput: {num_requests/total_time:.1f} req/s")
        
        # Extract metrics from results
        response_times = [r['response_time'] for r in results]
        threat_levels = [r['threat_level'] for r in results]
        actions = [r['action'] for r in results]
        
        # Calculate detection and blocking statistics
        malicious_count = sum(1 for tl in threat_levels if tl > 0.7)  # High threat count
        blocked_count = sum(1 for action in actions if action == 'BLOCK')  # Blocked requests
        
        print(f"  Malicious detected: {malicious_count}/{num_requests}")
        print(f"  Requests blocked: {blocked_count}/{num_requests}")
        
        # Should detect malicious requests (40% of workload expected)
        expected_malicious = num_requests * 0.4  # 40% malicious in test workload
        detection_rate = malicious_count / expected_malicious if expected_malicious > 0 else 1.0
        
        # Require 80% detection rate
        assert detection_rate > 0.8, \
            f"Malicious detection rate too low: {detection_rate*100:.1f}%"
        
        # Performance should be stable (no excessive spikes)
        if response_times:
            avg_response = statistics.mean(response_times)
            max_response = max(response_times)
            
            print(f"  Avg response time: {avg_response:.3f}s")
            print(f"  Max response time: {max_response:.3f}s")
            
            # Max response should not be more than 10x average
            assert max_response < avg_response * 10, \
                f"Response time spikes too high: max={max_response:.3f}s, avg={avg_response:.3f}s"

# Main execution block for direct script running
if __name__ == "__main__":
    # Allow running tests directly from command line
    pytest.main([__file__, "-v"])