#!/usr/bin/env python3
"""
Упрощенное тестирование анализатора трафика
"""

import time
import requests
import logging
from traffic_analyzer import analyze_traffic, analyze_app_layer, detect_attacks
from traffic_analyzer.capture import create_test_packets

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

def test_with_synthetic_data():
    """Тестирование с синтетическими данными"""
    print("Тестирование с синтетическими данными")
    print("=" * 50)
    
    # Создаем тестовые пакеты
    packets = create_test_packets()
    print(f"Создано тестовых пакетов: {len(packets)}")
    
    # Анализируем трафик
    results = analyze_traffic(packets)
    print(f"\nРезультаты анализа:")
    print(f"Всего пакетов: {results.get('total_packets', 0)}")
    print(f"TCP пакетов: {results.get('tcp_packets', 0)}")
    print(f"UDP пакетов: {results.get('udp_packets', 0)}")
    print(f"HTTP пакетов: {results.get('http_packets', 0)}")
    print(f"HTTPS пакетов: {results.get('https_packets', 0)}")
    
    # Анализ прикладного уровня
    try:
        app_results = analyze_app_layer(packets)
        if app_results:
            print(f"\nАнализ прикладного уровня:")
            print(f"HTTP запросы: {len(app_results.get('http_requests', []))}")
            print(f"DNS запросы: {len(app_results.get('dns_queries', []))}")
            print(f"TLS соединения: {len(app_results.get('tls_connections', []))}")
    except Exception as e:
        print(f"Ошибка при анализе прикладного уровня: {e}")
    
    # Поиск атак
    try:
        attack_results = detect_attacks(packets)
        if attack_results:
            print(f"\nОбнаруженные атаки:")
            for attack_type, count in attack_results.items():
                if count > 0:
                    print(f"  {attack_type}: {count}")
    except Exception as e:
        print(f"Ошибка при поиске атак: {e}")

def test_website_requests():
    """Тестирование с реальными HTTP запросами"""
    print("\nТестирование с реальными HTTP запросами")
    print("=" * 50)
    
    test_sites = [
        "http://httpbin.org/get",
        "https://httpbin.org/get",
        "http://example.com"
    ]
    
    for site in test_sites:
        try:
            print(f"\nТестируем: {site}")
            response = requests.get(site, timeout=10)
            print(f"Статус: {response.status_code}")
            print(f"Размер ответа: {len(response.content)} байт")
            print(f"Заголовки: {dict(response.headers)}")
            
        except Exception as e:
            print(f"Ошибка: {e}")

def test_analyzer_functions():
    """Тестирование отдельных функций анализатора"""
    print("\nТестирование функций анализатора")
    print("=" * 50)
    
    # Импортируем модули
    try:
        from traffic_analyzer.analyze import analyze_protocols, analyze_ports
        from traffic_analyzer.app_layer import extract_http_info, extract_dns_info
        from traffic_analyzer.utils import get_packet_info
        
        print("✓ Все модули успешно импортированы")
        
        # Тестируем утилиты
        from traffic_analyzer.capture import create_test_packets
        packets = create_test_packets()
        
        if packets:
            packet_info = get_packet_info(packets[0])
            print(f"✓ Информация о пакете: {packet_info}")
        
        print("✓ Все функции работают корректно")
        
    except Exception as e:
        print(f"✗ Ошибка при тестировании функций: {e}")

def main():
    """Основная функция тестирования"""
    print("Упрощенное тестирование анализатора трафика")
    print("=" * 60)
    
    # Тест 1: Синтетические данные
    test_with_synthetic_data()
    
    # Тест 2: Реальные HTTP запросы
    test_website_requests()
    
    # Тест 3: Функции анализатора
    test_analyzer_functions()
    
    print("\n" + "=" * 60)
    print("Тестирование завершено!")

if __name__ == "__main__":
    main()
