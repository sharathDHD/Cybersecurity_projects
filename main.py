import logging

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')


from flask import Flask, render_template, request, redirect, url_for
import subprocess
import asyncio
import threading

app = Flask(__name__, static_folder='static')

def read_from_process(process):
    """Read output from the process."""
    while True:
        line = process.stdout.readline().decode('utf-8')
        print(line, end='')  # Print the output to console for now

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        command = request.form['command']
        safe_command = command.replace(";", "").replace("&", "")
        
        logging.info(f"Executing command: {safe_command}")
        
        if safe_command.startswith("python"):
            # Start the Python script as a subprocess
            process = subprocess.Popen(safe_command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Start a thread to read from the process asynchronously
            threading.Thread(target=read_from_process, args=(process,), daemon=True).start()
            
            # Example: Send input to the subprocess
            process.stdin.write('first_input\n')
            process.stdin.write('second_input\n')
            process.stdin.flush()
            
            logging.info("Command executed successfully.")
        else:
            try:
                output = subprocess.check_output(safe_command, stderr=subprocess.STDOUT, shell=True).decode()
                logging.info("Command executed successfully.")
            except subprocess.CalledProcessError as e:
                output = str(e.output)
                logging.error(f"Error during execution: {output}")
        return render_template('index.html', output=output)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
