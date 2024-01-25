import socket
import threading
import time
import header as Header


class KeepAliveManager:
    def __init__(self):
        # set up keep alive thread
        self.closing = False
        self.keep_alive_thread = None
        self.stop_flag = threading.Event()

    def keep_alive(self, client_sock, server_address):
        exit_counter = 0
        while not self.stop_flag.is_set():
            client_sock.settimeout(5)
            try:
                # Check if the socket is still open before setting a timeout
                if client_sock.fileno() < 0:
                    break

                # Send keep alive message
                mess = Header.create_header(0, 0, 0, 0, "keepalive", False)
                client_sock.sendto(mess, server_address)

                # Wait for reply
                reply, _ = client_sock.recvfrom(1500)

                flag, _, _, _, _, _ = Header.decode_header(reply)

                # If the server responds with a keep alive message, wait 5 seconds and do it again
                if flag == 0:
                    exit_counter = 0
                    pass

            except ConnectionResetError:
                print(
                    "(KA) Server is not running or unreachable. Exiting... PLEASE PRESS ENTER"
                )
                self.set_closing()
                return
            except socket.timeout:
                exit_counter += 1
                print(
                    f"(KA) Server is not responding. Trying again... ({exit_counter}/3)"
                )
                if exit_counter == 3:
                    print("Server is not responding. Exiting... PLEASE PRESS ENTER")
                    self.set_closing()
                    return
                continue
            except OSError as e:
                print(
                    f"(KA) An unexpected error occurred: {e} . Exiting... PLEASE PRESS ENTER"
                )
                self.set_closing()
                return

            # Wait 5 seconds before sending another keep alive message
            time.sleep(5)

    def start_keep_alive(self, client_socket, server_address):
        # set up keep alive thread
        self.closing = False
        self.stop_flag.clear()
        self.keep_alive_thread = threading.Thread(
            target=self.keep_alive,
            args=(client_socket, server_address),
        )
        self.keep_alive_thread.daemon = True
        self.keep_alive_thread.start()

    def stop_keep_alive(self):
        # stop keep alive thread by setting stop flag and joining thread
        self.stop_flag.set()
        if self.keep_alive_thread:
            self.keep_alive_thread.join()
            self.keep_alive_thread = None

    def restart_keep_alive(self, client_socket, server_address):
        # restart keep alive thread
        self.stop_keep_alive()
        self.start_keep_alive(client_socket, server_address)

    def set_closing(self):
        # set closing flag
        self.closing = True

    def get_closing(self):
        # get closing flag
        return self.closing
