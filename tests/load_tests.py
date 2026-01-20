# tests/load_tests.py
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
        # Arrange
        agent = threat_detection_agent
        num_concurrent = 10
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        results = []
        errors = []
        
        # Define worker function
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
        
        # Act: Execute concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all requests
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
        
        # Assert
        assert len(errors) == 0, f"Should handle concurrent requests without errors: {errors}"
        assert len(results) == num_concurrent, f"Should process all requests: {len(results)}/{num_concurrent}"
        
        # Calculate statistics
        response_times = [r['response_time'] for r in results]
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        
        # Response times should be reasonable
        assert avg_response_time < 0.5, f"Average response time too high: {avg_response_time:.3f}s"
        assert max_response_time < 1.0, f"Maximum response time too high: {max_response_time:.3f}s"
        
        # All requests should detect threat
        threat_levels = [r['threat_level'] for r in results]
        assert all(tl > 0.5 for tl in threat_levels), \
            f"All requests should detect threat, got min={min(threat_levels):.3f}"
        
        print(f"Concurrent requests ({num_concurrent}): "
              f"avg_time={avg_response_time:.3f}s, "
              f"max_time={max_response_time:.3f}s, "
              f"success_rate={len(results)/num_concurrent*100:.1f}%")
    
    def test_multi_agent_concurrent_coordination(self, agent_orchestrator):
        """Test multi-agent coordination under concurrent load"""
        # Arrange
        orchestrator = agent_orchestrator
        num_concurrent = 5
        
        # Different types of requests
        request_types = [
            {
                'name': 'xss_attack',
                'data': {
                    'url': 'https://test.com/?q=<script>alert(1)</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'sqli_attack',
                'data': {
                    'url': 'https://test.com/login?user=admin&pass=%27OR%271%27%3D%271',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'normal_traffic',
                'data': {
                    'url': 'https://test.com/about',
                    'headers': {'User-Agent': 'Mozilla/5.0'},
                    'body': '',
                    'method': 'GET'
                }
            }
        ]
        
        results = []
        errors = []
        
        # Define worker function
        def coordinate_analysis(request_type: Dict, request_id: int):
            try:
                start_time = time.time()
                result = orchestrator.coordinate_analysis(request_type['data'])
                end_time = time.time()
                
                return {
                    'request_id': request_id,
                    'type': request_type['name'],
                    'success': True,
                    'response_time': end_time - start_time,
                    'threat_level': result['final_decision']['threat_level']
                }
            except Exception as e:
                return {
                    'request_id': request_id,
                    'type': request_type['name'],
                    'success': False,
                    'error': str(e)
                }
        
        # Create mixed workload
        workload = []
        for i in range(num_concurrent):
            request_type = random.choice(request_types)
            workload.append((request_type, i))
        
        # Act: Execute concurrent coordination
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all requests
            future_to_req = {
                executor.submit(coordinate_analysis, req_type, req_id): (req_type, req_id)
                for req_type, req_id in workload
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_req):
                result = future.result()
                if result['success']:
                    results.append(result)
                else:
                    errors.append(result)
        
        # Assert
        assert len(errors) == 0, f"Should handle concurrent coordination: {errors}"
        
        # Calculate statistics
        response_times = [r['response_time'] for r in results]
        if response_times:
            avg_response_time = statistics.mean(response_times)
            max_response_time = max(response_times)
            
            # Coordination takes more time than single agent
            assert avg_response_time < 2.0, f"Average coordination time too high: {avg_response_time:.3f}s"
            
            print(f"Multi-agent concurrent coordination ({num_concurrent}): "
                  f"avg_time={avg_response_time:.3f}s, "
                  f"max_time={max_response_time:.3f}s")

class TestHighVolumeLoad:
    """Tests for high volume request handling"""
    
    def test_high_volume_requests(self, threat_detection_agent):
        """Test handling high volume of requests"""
        # Arrange
        agent = threat_detection_agent
        num_requests = 100  # High volume
        
        # Generate variety of requests
        requests = []
        for i in range(num_requests):
            # Mix of malicious and benign
            if i % 4 == 0:  # 25% malicious
                payload = '<script>alert("XSS")</script>'
            elif i % 4 == 1:  # 25% SQLi
                payload = "' OR '1'='1"
            else:  # 50% benign
                payload = f'legitimate_query_{i}'
            
            requests.append({
                'url': f'https://test.com/?q={payload}',
                'headers': {},
                'body': '',
                'method': 'GET'
            })
        
        response_times = []
        threat_levels = []
        
        # Act: Process high volume sequentially
        start_total = time.time()
        
        for i, request in enumerate(requests):
            request_start = time.time()
            result = agent.analyze(request)
            request_end = time.time()
            
            response_times.append(request_end - request_start)
            threat_levels.append(result['threat_level'])
            
            # Progress indicator for large tests
            if (i + 1) % 20 == 0:
                print(f"  Processed {i + 1}/{num_requests} requests")
        
        end_total = time.time()
        total_time = end_total - start_total
        
        # Assert
        # No crashes during high volume
        assert len(response_times) == num_requests, \
            f"Should process all {num_requests} requests"
        
        # Calculate throughput
        throughput = num_requests / total_time
        
        # Performance metrics
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        print(f"\nHigh Volume Test ({num_requests} requests):")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {throughput:.1f} requests/second")
        print(f"  Avg response time: {avg_response_time:.3f}s")
        print(f"  95th percentile: {p95_response_time:.3f}s")
        
        # Should maintain reasonable throughput
        assert throughput > 10, f"Throughput too low: {throughput:.1f} requests/second"
        
        # Response time should not degrade excessively
        assert p95_response_time < avg_response_time * 3, \
            f"Response time degradation too high: p95={p95_response_time:.3f}s, avg={avg_response_time:.3f}s"
    
    def test_sustained_load(self, threat_detection_agent):
        """Test sustained load over time"""
        # Arrange
        agent = threat_detection_agent
        duration = 30  # seconds
        requests_per_second = 5
        
        total_requests = duration * requests_per_second
        request_count = 0
        response_times = []
        
        # Create request template
        request_template = {
            'url': 'https://test.com/?q=test',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        # Act: Sustained load
        start_time = time.time()
        end_time = start_time + duration
        
        print(f"Starting sustained load test: {duration}s at {requests_per_second} req/s")
        
        while time.time() < end_time:
            batch_start = time.time()
            
            # Process batch of requests
            for _ in range(requests_per_second):
                request_start = time.time()
                result = agent.analyze(request_template)
                request_end = time.time()
                
                response_times.append(request_end - request_start)
                request_count += 1
            
            batch_end = time.time()
            batch_time = batch_end - batch_start
            
            # Throttle to maintain rate
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
        
        total_time = time.time() - start_time
        actual_rate = request_count / total_time
        
        # Assert
        print(f"\nSustained Load Test:")
        print(f"  Target: {requests_per_second} req/s for {duration}s")
        print(f"  Actual: {actual_rate:.1f} req/s for {total_time:.1f}s")
        print(f"  Total requests: {request_count}")
        
        if response_times:
            avg_response = statistics.mean(response_times)
            max_response = max(response_times)
            
            print(f"  Avg response time: {avg_response:.3f}s")
            print(f"  Max response time: {max_response:.3f}s")
            
            # Should maintain stable performance
            assert max_response < avg_response * 5, \
                f"Response time spikes too high: max={max_response:.3f}s, avg={avg_response:.3f}s"
            
            # Should achieve target rate (±20%)
            assert abs(actual_rate - requests_per_second) / requests_per_second < 0.2, \
                f"Rate deviation too high: target={requests_per_second}, actual={actual_rate:.1f}"

class TestMemoryUsage:
    """Tests for memory usage under load"""
    
    def test_memory_usage_single_agent(self, threat_detection_agent):
        """Test memory usage of single agent"""
        # Arrange
        agent = threat_detection_agent
        num_requests = 50
        
        # Track memory (approximate)
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Act: Process requests
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        for i in range(num_requests):
            result = agent.analyze(request_data)
            assert result['threat_level'] > 0.5, "Should detect threat"
        
        # Get final memory
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Assert
        print(f"\nMemory Usage Test (Single Agent):")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory increase: {memory_increase:.1f} MB")
        print(f"  Requests processed: {num_requests}")
        
        # Memory increase should be reasonable
        # Allow some increase for caching/optimization
        assert memory_increase < 50, f"Memory leak suspected: increased by {memory_increase:.1f} MB"
        
        # Memory per request should be low
        memory_per_request = memory_increase / num_requests
        assert memory_per_request < 0.5, f"Memory per request too high: {memory_per_request:.2f} MB/request"
    
    def test_memory_usage_multi_agent(self, agent_orchestrator):
        """Test memory usage with multi-agent coordination"""
        # Arrange
        orchestrator = agent_orchestrator
        num_requests = 30
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Act: Process coordinated requests
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        for i in range(num_requests):
            result = orchestrator.coordinate_analysis(request_data)
            assert result['final_decision']['threat_level'] > 0.5, "Should detect threat"
        
        # Get final memory
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Assert
        print(f"\nMemory Usage Test (Multi-Agent):")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory increase: {memory_increase:.1f} MB")
        print(f"  Requests processed: {num_requests}")
        
        # Multi-agent uses more memory but should still be reasonable
        assert memory_increase < 100, f"Memory leak suspected: increased by {memory_increase:.1f} MB"

class TestScalability:
    """Tests for system scalability"""
    
    def test_scaling_with_request_complexity(self, threat_detection_agent):
        """Test how performance scales with request complexity"""
        # Arrange
        agent = threat_detection_agent
        
        # Requests of increasing complexity
        complexity_levels = [
            {
                'name': 'simple',
                'data': {
                    'url': 'https://test.com/',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'medium',
                'data': {
                    'url': 'https://test.com/?q=test&user=admin&session=abc123',
                    'headers': {'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'},
                    'body': '',
                    'method': 'GET'
                }
            },
            {
                'name': 'complex',
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
        
        results = []
        
        # Act: Measure each complexity level
        for level in complexity_levels:
            response_times = []
            
            # Run multiple times for statistical significance
            for _ in range(10):
                start_time = time.time()
                result = agent.analyze(level['data'])
                end_time = time.time()
                
                response_times.append(end_time - start_time)
            
            avg_time = statistics.mean(response_times)
            std_time = statistics.stdev(response_times) if len(response_times) > 1 else 0
            
            results.append({
                'level': level['name'],
                'avg_time': avg_time,
                'std_time': std_time
            })
        
        # Assert
        print(f"\nScalability with Complexity:")
        for result in results:
            print(f"  {result['level']}: avg={result['avg_time']:.3f}s ±{result['std_time']:.3f}s")
        
        # Complex requests should take longer but not exponentially
        simple_time = results[0]['avg_time']
        complex_time = results[-1]['avg_time']
        
        complexity_ratio = complex_time / simple_time
        
        assert complexity_ratio < 10, \
            f"Complexity scaling too high: simple={simple_time:.3f}s, complex={complex_time:.3f}s, ratio={complexity_ratio:.1f}"
        
        # Variation should be reasonable
        for result in results:
            assert result['std_time'] < result['avg_time'] * 0.5, \
                f"Response time too variable for {result['level']}: std={result['std_time']:.3f}s"
    
    def test_agent_count_scalability(self):
        """Test how performance scales with number of agents"""
        # Note: This test creates multiple agent instances
        # and measures coordination overhead
        
        pytest.skip("Agent count scalability test requires dynamic agent creation")
        # Implementation would create orchestrators with different agent counts
        # and measure coordination time

class TestStressTesting:
    """Stress tests beyond normal limits"""
    
    def test_extreme_concurrency(self, threat_detection_agent):
        """Test extreme concurrency levels"""
        # Arrange
        agent = threat_detection_agent
        num_concurrent = 50  # Extreme concurrency
        
        request_data = {
            'url': 'https://test.com/?q=<script>alert("XSS")</script>',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        results = []
        errors = []
        
        # Define worker function
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
        
        # Act: Extreme concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            # Submit all requests
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
        
        # Assert
        success_rate = len(results) / num_concurrent
        
        print(f"\nExtreme Concurrency Test ({num_concurrent} concurrent):")
        print(f"  Success rate: {success_rate*100:.1f}%")
        print(f"  Errors: {len(errors)}")
        
        if errors:
            for error in errors[:3]:  # Show first few errors
                print(f"    Error in request {error['request_id']}: {error['error'][:100]}...")
        
        # Should handle most requests even under extreme load
        assert success_rate > 0.8, f"Success rate too low under extreme concurrency: {success_rate*100:.1f}%"
        
        if results:
            response_times = [r['response_time'] for r in results]
            avg_time = statistics.mean(response_times)
            max_time = max(response_times)
            
            print(f"  Avg response time: {avg_time:.3f}s")
            print(f"  Max response time: {max_time:.3f}s")
    
    def test_very_large_payloads(self, threat_detection_agent):
        """Test handling of very large request payloads"""
        # Arrange
        agent = threat_detection_agent
        
        # Generate large payloads
        large_payloads = [
            {
                'name': 'large_json',
                'data': {
                    'url': 'https://api.test.com/data',
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'data': 'A' * 10000}),  # 10KB JSON
                    'method': 'POST'
                }
            },
            {
                'name': 'large_form',
                'data': {
                    'url': 'https://test.com/upload',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'body': '&'.join([f'field{i}=value{"B"*100}' for i in range(100)]),  # ~10KB
                    'method': 'POST'
                }
            },
            {
                'name': 'large_xss',
                'data': {
                    'url': 'https://test.com/?q=' + '<script>' + 'alert("X");' * 1000 + '</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                }
            }
        ]
        
        for payload_test in large_payloads:
            # Act
            start_time = time.time()
            
            try:
                result = agent.analyze(payload_test['data'])
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Assert: Should handle large payloads
                assert response_time < 5.0, \
                    f"{payload_test['name']}: Response time too high for large payload: {response_time:.2f}s"
                
                # Should not crash
                assert 'threat_level' in result, \
                    f"{payload_test['name']}: Should return result with threat_level"
                
                print(f"✓ {payload_test['name']}: handled in {response_time:.2f}s, threat={result['threat_level']:.2f}")
                
            except Exception as e:
                pytest.fail(f"{payload_test['name']}: Failed to handle large payload: {e}")

class TestPerformanceMonitoring:
    """Tests for performance monitoring and metrics"""
    
    def test_performance_metrics_collection(self, agent_orchestrator):
        """Test collection of performance metrics"""
        # Arrange
        orchestrator = agent_orchestrator
        
        # Process some requests to generate metrics
        requests = [
            {
                'url': 'https://test.com/?q=<script>alert(1)</script>',
                'headers': {},
                'body': '',
                'method': 'GET'
            },
            {
                'url': 'https://test.com/about',
                'headers': {},
                'body': '',
                'method': 'GET'
            }
        ]
        
        for request in requests:
            orchestrator.coordinate_analysis(request)
        
        # Act: Get system status/metrics
        if hasattr(orchestrator, 'get_system_status'):
            status = orchestrator.get_system_status()
        else:
            pytest.skip("System status method not available")
        
        # Assert: Should contain performance metrics
        assert 'metrics' in status, "System status should contain metrics"
        
        metrics = status['metrics']
        
        # Check expected metrics
        expected_metrics = ['total_analyses', 'threats_detected']
        for metric in expected_metrics:
            assert metric in metrics, f"Should contain {metric} metric"
        
        # Metrics should be numeric
        assert isinstance(metrics['total_analyses'], (int, float)), \
            "total_analyses should be numeric"
        
        # Print metrics for monitoring
        print(f"\nPerformance Metrics:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
        # Should have processed our requests
        assert metrics['total_analyses'] >= len(requests), \
            f"Should track total analyses: {metrics['total_analyses']} >= {len(requests)}"
    
    def test_response_time_tracking(self, threat_detection_agent):
        """Test tracking of response time percentiles"""
        # Arrange
        agent = threat_detection_agent
        num_requests = 100
        
        request_data = {
            'url': 'https://test.com/?q=test',
            'headers': {},
            'body': '',
            'method': 'GET'
        }
        
        response_times = []
        
        # Act: Collect response times
        for i in range(num_requests):
            start_time = time.time()
            result = agent.analyze(request_data)
            end_time = time.time()
            
            response_times.append(end_time - start_time)
            
            # Add some variability
            time.sleep(random.uniform(0.001, 0.01))
        
        # Calculate percentiles
        response_times.sort()
        
        percentiles = {
            'p50': response_times[int(num_requests * 0.5)],
            'p90': response_times[int(num_requests * 0.9)],
            'p95': response_times[int(num_requests * 0.95)],
            'p99': response_times[int(num_requests * 0.99)],
        }
        
        # Assert: Percentiles should be reasonable
        print(f"\nResponse Time Percentiles ({num_requests} requests):")
        for percentile, value in percentiles.items():
            print(f"  {percentile}: {value:.3f}s")
        
        # p99 should not be too much worse than p50
        p99_to_p50_ratio = percentiles['p99'] / percentiles['p50']
        assert p99_to_p50_ratio < 5, \
            f"p99 too high relative to p50: ratio={p99_to_p50_ratio:.1f}"
        
        # All percentiles should be within reasonable bounds
        max_allowed = 1.0  # 1 second maximum
        for percentile, value in percentiles.items():
            assert value < max_allowed, \
                f"{percentile} response time too high: {value:.3f}s > {max_allowed}s"

@pytest.mark.integration
class TestEndToEndLoad:
    """End-to-end load testing"""
    
    def test_complete_system_load(self, agent_orchestrator):
        """Test complete system under mixed load"""
        # Arrange
        orchestrator = agent_orchestrator
        num_requests = 50
        
        # Mixed workload
        workload = []
        for i in range(num_requests):
            # Distribute request types
            if i % 5 == 0:  # 20% malicious
                workload.append({
                    'url': f'https://test.com/?q=<script>alert({i})</script>',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                })
            elif i % 5 == 1:  # 20% SQLi
                workload.append({
                    'url': f'https://test.com/login?user=admin&pass=%27OR%27{i}%27%3D%27{i}',
                    'headers': {},
                    'body': '',
                    'method': 'GET'
                })
            else:  # 60% normal
                workload.append({
                    'url': f'https://test.com/page{i}',
                    'headers': {'User-Agent': 'Mozilla/5.0'},
                    'body': '',
                    'method': 'GET'
                })
        
        results = []
        start_time = time.time()
        
        # Act: Process mixed workload
        for i, request in enumerate(workload):
            request_start = time.time()
            
            result = orchestrator.coordinate_analysis(request)
            
            request_end = time.time()
            
            results.append({
                'request_id': i,
                'response_time': request_end - request_start,
                'threat_level': result['final_decision']['threat_level'],
                'action': result['final_decision']['action']
            })
            
            # Progress
            if (i + 1) % 10 == 0:
                print(f"  Processed {i + 1}/{num_requests} requests")
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Assert
        print(f"\nComplete System Load Test:")
        print(f"  Total requests: {num_requests}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Overall throughput: {num_requests/total_time:.1f} req/s")
        
        # Calculate statistics
        response_times = [r['response_time'] for r in results]
        threat_levels = [r['threat_level'] for r in results]
        actions = [r['action'] for r in results]
        
        # Malicious requests should be blocked
        malicious_count = sum(1 for tl in threat_levels if tl > 0.7)
        blocked_count = sum(1 for action in actions if action == 'BLOCK')
        
        print(f"  Malicious detected: {malicious_count}/{num_requests}")
        print(f"  Requests blocked: {blocked_count}/{num_requests}")
        
        # Should detect malicious requests
        expected_malicious = num_requests * 0.4  # 40% of our workload
        detection_rate = malicious_count / expected_malicious
        
        assert detection_rate > 0.8, \
            f"Malicious detection rate too low: {detection_rate*100:.1f}%"
        
        # Performance should be stable
        avg_response = statistics.mean(response_times)
        max_response = max(response_times)
        
        print(f"  Avg response time: {avg_response:.3f}s")
        print(f"  Max response time: {max_response:.3f}s")
        
        assert max_response < avg_response * 10, \
            f"Response time spikes too high: max={max_response:.3f}s, avg={avg_response:.3f}s"

if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])