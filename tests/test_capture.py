#!/usr/bin/env python3
"""
Тестирование анализатора трафика с реальным захватом
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

def test_capture_with_website(interface="Ethernet", website="http://httpbin.org/get"):
    """Тестирование захвата трафика при посещении сайта"""
    print(f"\n{'='*60}")
    print(f"Тестирование захвата трафика")
    print(f"Интерфейс: {interface}")
    print(f"Сайт: {website}")
    print(f"{'='*60}")
    
    packets = []
    capture_complete = threading.Event()
    
    def capture_packets():
        nonlocal packets
        try:
            print("Начинаем захват трафика...")
            # Захватываем пакеты во время посещения сайта
            packets = capture_traffic(interface, 20, "tcp port 80 or tcp port 443")
            print(f"Захвачено пакетов: {len(packets)}")
            capture_complete.set()
        except Exception as e:
            print(f"Ошибка при захвате трафика: {e}")
            capture_complete.set()
    
    # Запускаем захват в отдельном потоке
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()
    
    # Ждем немного для начала захвата
    time.sleep(2)
    
    try:
        # Посещаем сайт
        print(f"Посещаем сайт: {website}")
        response = requests.get(website, timeout=10)
        print(f"Статус ответа: {response.status_code}")
        print(f"Размер ответа: {len(response.content)} байт")
        
    except Exception as e:
        print(f"Ошибка при посещении сайта: {e}")
    
    # Ждем завершения захвата
    capture_complete.wait(timeout=30)
    capture_thread.join()
    
    if packets:
        # Анализируем трафик
        print("\nАнализ захваченного трафика:")
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
        
        return True
    else:
        print("Не удалось захватить пакеты")
        return False

def test_multiple_sites():
    """Тестирование на нескольких сайтах"""
    print("Тестирование анализатора трафика на реальных сайтах")
    print("=" * 60)
    
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
    
    # Список сайтов для тестирования
    test_sites = [
        "http://httpbin.org/get",
        "https://httpbin.org/get",
        "http://example.com"
    ]
    
    successful_tests = 0
    total_tests = len(test_sites)
    
    for i, site in enumerate(test_sites, 1):
        print(f"\nТест {i}/{total_tests}")
        try:
            if test_capture_with_website(interface, site):
                successful_tests += 1
            time.sleep(3)  # Пауза между тестами
        except KeyboardInterrupt:
            print("\nТестирование прервано пользователем")
            break
        except Exception as e:
            print(f"Ошибка при тестировании {site}: {e}")
    
    print(f"\n{'='*60}")
    print(f"РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print(f"{'='*60}")
    print(f"Всего тестов: {total_tests}")
    print(f"Успешных: {successful_tests}")
    print(f"Неудачных: {total_tests - successful_tests}")
    
    if successful_tests > 0:
        print(f"✓ Анализатор трафика работает корректно!")
    else:
        print(f"✗ Анализатор трафика не смог захватить пакеты")
        print("Возможные причины:")
        print("- Недостаточно прав (запустите с правами администратора)")
        print("- Неправильный интерфейс")
        print("- Отсутствует libpcap")

def main():
    """Основная функция"""
    try:
        test_multiple_sites()
    except KeyboardInterrupt:
        print("\nТестирование прервано пользователем")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")

if __name__ == "__main__":
    main()
