import socket
import time

# Configuration
HOST = '0.0.0.0'  # Localhost on the server
PORT = 5000         # The port your C code will ask for


while True:
    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            # Allow immediate reuse of the port after restart
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            s.bind((HOST, PORT))
            s.listen(1)
            print(f"Python: Waiting for SSHD to connect on {HOST}:{PORT}...")

            # This blocks until the C code calls ssh_channel_open_forward
            conn, addr = s.accept()
            
            with conn:
                print(f"Python: Connected by {addr}! Sending data...")
                # Prepare your binary data
                data = b'Hello world'
                
                # Send the data through the socket
                while (True):
                    conn.send(data)
                    print("Python: Data sent. Closing connection.")
                    # Give the system a moment to flush buffers before exiting
                    time.sleep(1)
                    print("Done.")
    except KeyboardInterrupt:
        print("quitting")
        quit()
    except:
        print("retrying...")

