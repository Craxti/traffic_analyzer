import logging
import psutil
import time
from multiprocessing import Process, Queue
from traffic_analyzer.capture import capture_traffic
from traffic_analyzer.analyze import analyze_traffic
from traffic_analyzer.visualize import update_visualizations

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s]: %(message)s',
        handlers=[
            logging.FileHandler('traffic_analyzer.log'),
            logging.StreamHandler()
        ]
    )

def get_default_interface():
    return psutil.net_io_counters(pernic=True).keys().__iter__().__next__()

def data_processing(interface, packet_count, queue):
    packets = capture_traffic(interface, packet_count)
    results = analyze_traffic(packets)
    queue.put(results)

def real_time_visualization(queue):
    while True:
        results = queue.get()
        update_visualizations(results)
        time.sleep(5)

def main():
    setup_logger()

    interface = get_default_interface()
    packet_count = 10

    queue = Queue()

    process_data = Process(target=data_processing, args=(interface, packet_count, queue))
    process_viz = Process(target=real_time_visualization, args=(queue,))

    process_data.start()
    process_viz.start()

    process_data.join()
    process_viz.join()

if __name__ == "__main__":
    main()
