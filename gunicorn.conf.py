import multiprocessing
import os


bind = f"0.0.0.0:{os.getenv('APP_PORT', 8000)}"

workers = multiprocessing.cpu_count() * 2 + 1

worker_class = "uvicorn.workers.UvicornWorker"

max_requests = 1000

max_requests_jitter = 50

accesslog = "-"

errorlog = "-"

loglevel = "info"

timeout=30

preload_app = False