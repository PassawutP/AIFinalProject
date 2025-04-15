import requests
import time

# 1. Send a POST request to start the task
response = requests.post("http://localhost:8000/start-task/", json={"data": "some input"})
task_info = response.json()
task_id = task_info["task_id"]

print(f"Task started with ID: {task_id}")

# 2. Poll the status endpoint until the task finishes
status_url = f"http://localhost:8000/task-status/{task_id}"

while True:
    status_response = requests.get(status_url)
    status_data = status_response.json()
    
    status = status_data.get("status")
    print(f"Task status: {status}")

    if status == "SUCCESS":
        print(f"Task completed! Result: {status_data.get('result')}")
        break
    elif status == "FAILURE":
        print(f"Task failed! Error: {status_data.get('error')}")
        break
    else:
        # still running
        time.sleep(2)  # wait before polling again
