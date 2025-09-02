#!/usr/bin/env python3
"""
Тестирование анализатора трафика на реальных сайтах
"""

import time
import threading
import requests
import logging
from traffic_analyzer import capture_traffic, analyze_traffic, analyze_app_layer, detect_attacks

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

def visit_website(url, interface="Ethernet"):
    """Посещает веб-сайт и анализирует трафик"""
    print(f"\n{'='*60}")
    print(f"Тестирование сайта: {url}")
    print(f"{'='*60}")
    
    # Начинаем захват трафика в отдельном потоке
    capture_thread = None
    packets = []
    
    def capture_packets():
        nonlocal packets
        try:
            print(f"Начинаем захват трафика на интерфейсе: {interface}")
            # Захватываем пакеты во время посещения сайта
            packets = capture_traffic(interface, 50, "tcp port 80 or tcp port 443")
            print(f"Захвачено пакетов: {len(packets)}")
        except Exception as e:
            print(f"Ошибка при захвате трафика: {e}")
    
    # Запускаем захват трафика
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()
    
    # Ждем немного для начала захвата
    time.sleep(2)
    
    try:
        # Посещаем сайт
        print(f"Посещаем сайт: {url}")
        response = requests.get(url, timeout=10)
        print(f"Статус ответа: {response.status_code}")
        print(f"Размер ответа: {len(response.content)} байт")
        
    except Exception as e:
        print(f"Ошибка при посещении сайта: {e}")
    
    # Ждем завершения захвата
    capture_thread.join()
    
    if packets:
        # Анализируем трафик
        print("\nАнализ трафика:")
        print("-" * 40)
        
        # Базовый анализ
        results = analyze_traffic(packets)
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
    
    else:
        print("Не удалось захватить пакеты")

def main():
    """Основная функция тестирования"""
    print("Тестирование анализатора трафика на реальных сайтах")
    print("=" * 60)
    
    # Список сайтов для тестирования
    test_sites = [
        "http://httpbin.org/get",
        "https://httpbin.org/get", 
        "http://example.com",
        "https://www.google.com",
        "http://www.wikipedia.org"
    ]
    
    # Получаем доступные интерфейсы
    try:
        import psutil
        interfaces = list(psutil.net_if_addrs().keys())
        print(f"Доступные интерфейсы: {interfaces}")
        
        # Выбираем подходящий интерфейс
        interface = "Ethernet"  # По умолчанию
        for name in ["Ethernet", "Wi-Fi", "Беспроводная сеть"]:
            if name in interfaces:
                interface = name
                break
        print(f"Используем интерфейс: {interface}")
        
    except Exception as e:
        print(f"Ошибка при получении интерфейсов: {e}")
        interface = "Ethernet"
    
    # Тестируем каждый сайт
    for site in test_sites:
        try:
            visit_website(site, interface)
            time.sleep(3)  # Пауза между тестами
        except KeyboardInterrupt:
            print("\nТестирование прервано пользователем")
            break
        except Exception as e:
            print(f"Ошибка при тестировании {site}: {e}")
    
    print("\nТестирование завершено!")

if __name__ == "__main__":
    main()
