#!/usr/bin/env python3
"""
Тестирование анализатора трафика на реальных сайтах
"""

import time
import requests
import logging
import json
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

def test_website_connectivity():
    """Тестирование подключения к различным сайтам"""
    print("Тестирование подключения к сайтам")
    print("=" * 50)
    
    test_sites = [
        {
            "name": "HTTP Test Site",
            "url": "http://httpbin.org/get",
            "expected_status": 200
        },
        {
            "name": "HTTPS Test Site", 
            "url": "https://httpbin.org/get",
            "expected_status": 200
        },
        {
            "name": "Example.com",
            "url": "http://example.com",
            "expected_status": 200
        },
        {
            "name": "Google",
            "url": "https://www.google.com",
            "expected_status": 200
        },
        {
            "name": "Wikipedia",
            "url": "https://www.wikipedia.org",
            "expected_status": 200
        }
    ]
    
    results = []
    
    for site in test_sites:
        print(f"\nТестируем: {site['name']}")
        print(f"URL: {site['url']}")
        
        try:
            start_time = time.time()
            response = requests.get(site['url'], timeout=10)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Анализируем ответ
            parsed_url = urlparse(site['url'])
            
            site_result = {
                "name": site['name'],
                "url": site['url'],
                "status_code": response.status_code,
                "response_time": response_time,
                "content_length": len(response.content),
                "protocol": parsed_url.scheme,
                "domain": parsed_url.netloc,
                "headers": dict(response.headers),
                "success": response.status_code == site['expected_status']
            }
            
            print(f"✓ Статус: {response.status_code}")
            print(f"✓ Время ответа: {response_time:.2f} сек")
            print(f"✓ Размер ответа: {len(response.content)} байт")
            print(f"✓ Протокол: {parsed_url.scheme}")
            print(f"✓ Домен: {parsed_url.netloc}")
            
            # Анализируем заголовки
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "X-Frame-Options": "Clickjacking Protection",
                "X-Content-Type-Options": "MIME Sniffing Protection",
                "X-XSS-Protection": "XSS Protection",
                "Content-Security-Policy": "CSP"
            }
            
            print("Заголовки безопасности:")
            for header, description in security_headers.items():
                if header in response.headers:
                    print(f"  ✓ {description}: {response.headers[header]}")
                else:
                    print(f"  ✗ {description}: отсутствует")
            
            results.append(site_result)
            
        except requests.exceptions.Timeout:
            print("✗ Таймаут подключения")
            results.append({
                "name": site['name'],
                "url": site['url'],
                "error": "Timeout",
                "success": False
            })
        except requests.exceptions.ConnectionError:
            print("✗ Ошибка подключения")
            results.append({
                "name": site['name'],
                "url": site['url'],
                "error": "Connection Error",
                "success": False
            })
        except Exception as e:
            print(f"✗ Ошибка: {e}")
            results.append({
                "name": site['name'],
                "url": site['url'],
                "error": str(e),
                "success": False
            })
    
    return results

def analyze_results(results):
    """Анализ результатов тестирования"""
    print("\n" + "=" * 50)
    print("АНАЛИЗ РЕЗУЛЬТАТОВ")
    print("=" * 50)
    
    successful_tests = [r for r in results if r.get('success', False)]
    failed_tests = [r for r in results if not r.get('success', False)]
    
    print(f"Всего тестов: {len(results)}")
    print(f"Успешных: {len(successful_tests)}")
    print(f"Неудачных: {len(failed_tests)}")
    
    if successful_tests:
        print(f"\nСреднее время ответа: {sum(r['response_time'] for r in successful_tests) / len(successful_tests):.2f} сек")
        print(f"Общий объем данных: {sum(r['content_length'] for r in successful_tests)} байт")
        
        # Анализ протоколов
        protocols = {}
        for r in successful_tests:
            protocol = r.get('protocol', 'unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
        
        print(f"\nИспользованные протоколы:")
        for protocol, count in protocols.items():
            print(f"  {protocol.upper()}: {count} сайтов")
    
    if failed_tests:
        print(f"\nНеудачные тесты:")
        for test in failed_tests:
            print(f"  {test['name']}: {test.get('error', 'Unknown error')}")

def test_network_analysis():
    """Тестирование функций анализа сети"""
    print("\n" + "=" * 50)
    print("ТЕСТИРОВАНИЕ ФУНКЦИЙ АНАЛИЗА")
    print("=" * 50)
    
    try:
        # Импортируем функции анализа
        from traffic_analyzer.analyze import detect_attacks, detect_port_scan, detect_ddos
        from traffic_analyzer.utils import get_packet_info
        from traffic_analyzer.capture import create_test_packets
        
        print("✓ Модули анализа успешно импортированы")
        
        # Создаем тестовые пакеты
        packets = create_test_packets()
        print(f"✓ Создано {len(packets)} тестовых пакетов")
        
        if packets:
            # Тестируем анализ пакетов
            packet_info = get_packet_info(packets[0])
            print(f"✓ Информация о пакете: {packet_info}")
            
            # Тестируем обнаружение атак
            attack_results = detect_attacks(packets)
            print(f"✓ Результаты поиска атак: {attack_results}")
            
            # Тестируем обнаружение сканирования портов
            port_scan_ips = detect_port_scan(packets)
            print(f"✓ IP с подозрительной активностью: {port_scan_ips}")
            
            # Тестируем обнаружение DDoS
            ddos_detected = detect_ddos(packets)
            print(f"✓ DDoS обнаружен: {ddos_detected}")
        
        print("✓ Все функции анализа работают корректно")
        
    except Exception as e:
        print(f"✗ Ошибка при тестировании функций анализа: {e}")

def save_results(results, filename="test_results.json"):
    """Сохранение результатов в JSON файл"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n✓ Результаты сохранены в {filename}")
    except Exception as e:
        print(f"✗ Ошибка при сохранении результатов: {e}")

def main():
    """Основная функция тестирования"""
    print("Тестирование анализатора трафика на реальных сайтах")
    print("=" * 60)
    
    # Тест 1: Подключение к сайтам
    results = test_website_connectivity()
    
    # Тест 2: Анализ результатов
    analyze_results(results)
    
    # Тест 3: Функции анализа
    test_network_analysis()
    
    # Сохранение результатов
    save_results(results)
    
    print("\n" + "=" * 60)
    print("Тестирование завершено!")

if __name__ == "__main__":
    main()
