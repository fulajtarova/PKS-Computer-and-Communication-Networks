import socket
import time
import math
import os
import header as Header
import sending as Sendings
import receiving as Receiving
from keepalive import KeepAliveManager

# colors
OKGREEN = "\033[92m"
OKRED = "\033[91m"
OKMAGENTA = "\033[95m"
OKBLUE = "\033[94m"
RESET = "\033[0m"


"""
-------------------------------------------------------------------------------------------------------------
"""


def run_client(client_socket, server_address, client_address):
    print(OKMAGENTA + "\nCLIENT MODE" + RESET)

    print(f"Client address: {client_address}")
    print(f"Server address: {server_address}")

    client_socket.settimeout(15)

    try:
        # 5 attempts to establish connection
        for _ in range(5):
            # opening handshake
            print("\nSending SYN...")
            mess = Header.create_header(1, 0, 0, 0, "syn", False)
            client_socket.sendto(mess, server_address)

            reply, server_address = client_socket.recvfrom(1500)
            flag, _, _, _, _, _ = Header.decode_header(reply)
            if flag == 6:
                # connection established
                print("Rceived SYN-ACK")
                print("\nConnection established")
                break

            time.sleep(2)

        # start keep alive thread
        ka_manager = KeepAliveManager()
        ka_manager.start_keep_alive(client_socket, server_address)

        # client menu
        while not ka_manager.get_closing():
            print(OKBLUE + "\nClient Menu:")
            print("1 to send message")
            print("2 to send file")
            print("3 to switch mode")
            print("4 to close connection and exit" + RESET)

            choice = input("Enter choice: ")

            # check if keep alive thread is closing
            if ka_manager.get_closing():
                return 0, None

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            if choice == "1" or choice == "2":
                # send message or file
                file_name = None
                file_path = None
                if choice == "1":
                    data = input("Enter message: ")
                else:
                    file_name = input("Enter file name: ")
                    file_path = input("Enter file path: ")
                    while not os.path.isfile(file_path):
                        print("File does not exist")
                        file_name = input("Enter file name: ")
                        file_path = input("Enter file path: ")

                    # read data from file
                    with open(file_path, "rb") as file:
                        data = file.read()

                if ka_manager.get_closing():
                    return 0, None

                # get data size
                data_size = len(data)
                print(f"Data size: {data_size}")

                # get fragment size
                fragment_size = int(input("Enter fragment size: "))
                while fragment_size < 1 or fragment_size > (1500 - 8 - 20 - 16):
                    print("Invalid fragment size")
                    fragment_size = int(input("Enter fragment size: "))

                if ka_manager.get_closing():
                    return 0, None

                # get number of fragments by dividing data size by fragment size and rounding up
                if fragment_size > len(data):
                    num_fragments = 1
                else:
                    num_fragments = math.ceil(len(data) / fragment_size)

                print(f"Number of fragments: {num_fragments}")

                # ask if user wants to simulate data error
                simulate_error = input("Do you want to simulate data error? (y/n): ")
                error_indexes = []
                if simulate_error == "y":
                    fragments_with_error = input(
                        f"Enter fragments indexes with error separated by space from 0 to {num_fragments - 1}: "
                    )
                    error_indexes = [
                        int(fragment) for fragment in fragments_with_error.split()
                    ]

                if ka_manager.get_closing():
                    return 0, None

                simulate_error2 = input("Do you want to simulate lost packet? (y/n): ")
                error_indexes2 = []
                if simulate_error2 == "y":
                    fragments_with_error2 = input(
                        f"Enter fragments indexes with error separated by space from 0 to {num_fragments - 1}: "
                    )
                    error_indexes2 = [
                        int(fragment) for fragment in fragments_with_error2.split()
                    ]

                if ka_manager.get_closing():
                    return 0, None

                # stop keep alive thread
                ka_manager.stop_keep_alive()

                # set flag to 4 if message or 5 if file
                if choice == "1":
                    flag = 4
                else:
                    flag = 5

                # send initial message for message
                if choice == "1":
                    initial_message = Header.create_header(
                        flag,
                        fragment_size,
                        num_fragments,
                        0,
                        "initial",
                        False,
                    )
                else:
                    # send initial message for file with file name
                    initial_message = Header.create_header(
                        flag, fragment_size, num_fragments, 0, file_name, False
                    )

                client_socket.sendto(initial_message, server_address)

                # send data and wait for acknowledgement from server using stop and wait
                complete = Sendings.send_data(
                    flag,
                    fragment_size,
                    num_fragments,
                    server_address,
                    client_socket,
                    error_indexes,
                    error_indexes2,
                    data,
                    file_name,
                    file_path,
                )

                # if something went wrong restart keep alive thread
                if not complete:
                    ka_manager.restart_keep_alive(client_socket, server_address)
                else:
                    # if everything went well wait for server to switch mode, close connection or continue
                    print(
                        "\nWaiting if server wants to switch mode, close connection or continue..."
                    )

                    while True:
                        client_socket.settimeout(30)
                        try:
                            reply, server_address = client_socket.recvfrom(1500)
                            flag, _, _, _, _, data = Header.decode_header(reply)

                            if flag == 3:
                                # switch mode
                                print("Received SWITCH")
                                mess = Header.create_header(
                                    6, 0, 0, 0, "switchack", False
                                )
                                print("Sending SWITCH-ACK...")
                                client_socket.sendto(mess, server_address)
                                print("\nSwitching to server mode...\n")
                                return 3, client_address
                            elif flag == 2:
                                # close connection
                                print("Received FIN")
                                mess = Header.create_header(
                                    6, 0, 0, 0, "fineack", False
                                )
                                print("Sending FIN-ACK...")
                                client_socket.sendto(mess, server_address)
                                print("\nConnection closed\n")
                                return 0, None
                            else:
                                # continue
                                ka_manager.restart_keep_alive(
                                    client_socket, server_address
                                )
                                break
                        except socket.timeout:
                            print("No acknowledgement from server. Mode switch failed.")
                            ka_manager.restart_keep_alive(client_socket, server_address)
                            break

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif choice == "3":
                ka_manager.stop_keep_alive()

                # send switch message to the server
                print("Sending SWITCH...")
                mess = Header.create_header(3, 0, 0, 0, "switch", False)
                client_socket.sendto(mess, server_address)

                # receive switch message from the server
                reply, server_address = client_socket.recvfrom(1500)
                flag, _, _, _, _, _ = Header.decode_header(reply)

                if flag == 6:
                    # receive ACK
                    print("Received SWITCH-ACK")
                    print("\nSwitching to server mode...\n")
                    return 3, client_address
            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif choice == "4":
                ka_manager.stop_keep_alive()

                # send FIN
                print("Sending FIN...")
                mess = Header.create_header(2, 0, 0, 0, "fin", False)
                client_socket.sendto(mess, server_address)

                # receive FIN-ACK
                reply, server_address = client_socket.recvfrom(1500)
                flag, _, _, _, _, _ = Header.decode_header(reply)

                if flag == 6:
                    # receive ACK
                    print("Received FIN-ACK")
                    print("\nConnection closed\n")
                    return 0, None
            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            else:
                print("Invalid choice, try again")
            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    except ConnectionResetError:
        print("Server is not running or unreachable. Exiting...")
        return 0, None
    except socket.timeout:
        print("No data received, exiting...")
        return 0, None
    except OSError as e:
        if e.winerror == 10049:
            print("The requested address is not valid in its context. Exiting...")
            return 0, None
        print(f"An unexpected error occurred: {e}")
        return 0, None
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0, None


"""
-------------------------------------------------------------------------------------------------------------
"""


def run_server(server_socket, server_address):
    print(OKGREEN + "\nSERVER MODE" + RESET)
    print(f"Server address: {server_address}")

    exit_counter = 0

    while True:
        # set up timeout for 10 seconds and wait for data
        server_socket.settimeout(10)
        try:
            # decode header
            reply, client_address = server_socket.recvfrom(1500)

            (
                flag,
                _,
                _,
                frag_count,
                _,
                data,
            ) = Header.decode_header(reply)

            exit_counter = 0

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            if flag == 0:
                # keep alive
                print("Received keepalive")
                mess = Header.create_header(6, 0, 0, 0, "keepaliveack", False)
                server_socket.sendto(mess, client_address)

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif flag == 1:
                print("\nReceived SYN")
                # send SYN-ACK
                print("Sending SYN-ACK...")
                mess = Header.create_header(6, 0, 0, 0, "synack", False)
                server_socket.sendto(mess, client_address)

                print(f"\nConnection established with {client_address}\n")

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif flag == 2:
                # close connection
                print("Received FIN")
                # send FIN-ACK
                print("Sending FIN-ACK...")
                mess = Header.create_header(6, 0, 0, 0, "finack", False)
                server_socket.sendto(mess, client_address)

                print("\nConnection from client closed\n")

                return 0, None, None

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif flag == 3:
                # switch mode
                print("Received SWITCH")
                # send switch
                print("Sending SWITCHACK...")
                mess = Header.create_header(6, 0, 0, 0, "switchack", False)
                server_socket.sendto(mess, client_address)
                print("\nSwitching to client mode...\n")

                return 3, server_address, client_address

            # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
            elif flag == 4 or flag == 5:
                if flag == 4:
                    # message
                    print("\nRecieving message...")
                    Receiving.receiving_data(server_socket, None, frag_count)
                else:
                    # file
                    print("\nRecieving file...")
                    file_name = data.decode("utf-8")
                    Receiving.receiving_data(server_socket, file_name, frag_count)

                # ask if user wants to switch mode or close connection
                switch_choice = input(
                    OKRED
                    + "\n1 continue listening for data\n2 switch mode\n3 close connection\nEnter choice: "
                    + RESET
                )
                # if user wants to switch mode or close connection, send message to client and wait for acknowledgement
                if switch_choice == "2" or switch_choice == "3":
                    if switch_choice == "2":
                        print("\nSending SWITCH...")
                        mess = Header.create_header(3, 0, 0, 0, "switch", False)
                        server_socket.sendto(mess, client_address)
                    else:
                        print("\nSending FIN...")
                        mess = Header.create_header(2, 0, 0, 0, "fin", False)
                        server_socket.sendto(mess, client_address)

                    while True:
                        # wait for acknowledgement
                        try:
                            server_socket.settimeout(5)
                            reply, _ = server_socket.recvfrom(1500)
                            flag, _, _, _, _, _ = Header.decode_header(reply)
                            # if acknowledgement is received, switch mode or close connection
                            if flag == 6 and switch_choice == "2":
                                print("Received SWITCH-ACK")
                                print("\nSwitching to client mode...\n")
                                return 3, server_address, client_address
                            elif flag == 6 and switch_choice == "3":
                                print("Received FIN-ACK")
                                print("\nConnection closed\n")
                                return 0, None, None

                        except socket.timeout:
                            print(
                                "No acknowledgement from client. Continuing listening for data..."
                            )
                            break
                # if user wants to continue listening for data, send message to client and continue listening
                else:
                    mess = Header.create_header(7, 0, 0, 0, "nack", False)
                    server_socket.sendto(mess, client_address)
                    print("Continuing listening for data...\n")
        # --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

        except socket.timeout:
            exit_counter += 1
            print(f"No data received, waiting for new data... {exit_counter}/3")
            if exit_counter == 3:
                print("No data received for 30 seconds, exiting...")
                return 0, None, None
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            return 0, None, None


"""
-------------------------------------------------------------------------------------------------------------
"""


def switch_mode(current_mode, current_address, socket, old_client_address):
    # for client to run server mode
    if current_mode == "client":
        flag, server_address, client_address = run_server(socket, current_address)
        if flag == 3:
            switch_mode("server", server_address, socket, client_address)
        elif flag == 0:
            socket.close()
            main()

    # for server to run client mode
    if current_mode == "server":
        time.sleep(3)
        flag, client_address = run_client(socket, old_client_address, current_address)
        if flag == 3:
            switch_mode("client", client_address, socket, None)
        elif flag == 0:
            socket.close()
            main()


"""
-------------------------------------------------------------------------------------------------------------
"""


def main():
    while True:
        try:
            print(OKBLUE + "\nChoose your role or exit:")
            print("1 for server")
            print("2 for client")
            print("3 to exit" + RESET)

            choice = input("Enter choice: ")

            if choice == "1":
                # enter server ip and port
                server_ip = input("Enter server ip: ")
                server_port = int(input("Enter server port: "))

                # create server socket and bind it to server ip and port
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server_socket.bind((server_ip, server_port))

                flag, server_address, client_address = run_server(
                    server_socket, (server_ip, server_port)
                )
                # switching to client mode
                if flag == 3:
                    switch_mode("server", server_address, server_socket, client_address)
                # close connection and get back to main menu
                elif flag == 0:
                    server_socket.close()

            elif choice == "2":
                # enter server ip and port and client ip and port
                server_ip = input("Enter server ip: ")
                server_port = int(input("Enter server port: "))

                your_ip = input("Enter client ip: ")
                your_port = int(input("Enter client port: "))

                # create client socket and bind it to client ip and port
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.bind((your_ip, your_port))

                flag, client_address = run_client(
                    client_socket, (server_ip, server_port), (your_ip, your_port)
                )
                # switching to server mode
                if flag == 3:
                    switch_mode("client", client_address, client_socket, None)
                # close connection and get back to main menu
                elif flag == 0:
                    client_socket.close()

            elif choice == "3":
                print("\nExiting ...")
                exit()

            else:
                print("Invalid choice, try again")
        except Exception as e:
            print(f"An error occurred: {e}")
            continue


if __name__ == "__main__":
    main()
