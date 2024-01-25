import header as Header
import socket
import os

# colors for printing
OKCYAN = "\033[96m"
RESET = "\033[0m"
OKRED = "\033[91m"
OKYELLOW = "\033[93m"


def receiving_data(server_socket, file_name, initial_frag_count):
    # set up variables
    data = [None] * initial_frag_count
    correct_received_fragments = 0

    first_flag = True

    while True:
        # set up timeout for 11 seconds and wait for data
        server_socket.settimeout(20)
        try:
            # decode header
            reply, client_address = server_socket.recvfrom(1500)
            (
                flag,
                crc,
                frag_size,
                frag_count,
                frag_order,
                received_data,
            ) = Header.decode_header(reply)

            # check if flag is correct
            if flag != 4 and flag != 5 and flag != 6:
                print(
                    f"Received data with wrong flag, expected flag 4 or 5, received flag {flag}"
                )
                break

            # save flag for printing later
            if flag == 4 or flag == 5:
                mess_or_file_flag = flag

            # get last fragment that gives information about stop sending data
            if flag == 6:
                print("Client finished sending data")
                break

            # calculate crc and check if it matches
            new_crc = Header.calculate_crc(received_data)
            if new_crc != crc:
                # not sending anything, waiting for resend
                print(
                    f"Fragment {frag_order} recieved with error, crc not matching, waiting for resend"
                )
            else:
                # if fragment is not already received, save it
                if int(frag_order) == 0 and first_flag:
                    print(
                        f"Fragment {frag_order} received correctly, but not sending confirmation for first fragment"
                    )
                    data[frag_order] = received_data
                    correct_received_fragments += 1
                    first_flag = False
                    # dont send confirmation

                elif data[frag_order] is None:
                    print(f"Fragment {frag_order} received correctly")
                    data[frag_order] = received_data
                    correct_received_fragments += 1
                    # send confirmation
                    mess = Header.create_header(
                        6, frag_size, frag_count, frag_order, "ok", False
                    )
                    server_socket.sendto(mess, client_address)
                else:
                    # if fragment is already received, ignore it
                    print(f"Fragment {frag_order} already received, ignoring")
                    mess = Header.create_header(
                        6, frag_size, frag_count, frag_order, "ok", False
                    )
                    server_socket.sendto(mess, client_address)

        except socket.timeout:
            print("Timeout for 11 seconds, ending receiving data")
            break

    # check if all fragments were received correctly and print information
    if correct_received_fragments == frag_count:
        print(f"{OKYELLOW}\nSuccessfully received all fragments.{RESET}")
        if mess_or_file_flag == 4:
            for i in range(frag_count):
                data[i] = data[i].decode("utf-8")
            data = "".join(data)

            print(f"{OKCYAN}\nMessage: {data}\n")
            print(f"Message size: {len(data)}")
            print(f"Number of fragments: {frag_count}")
            print(f"Fragment size: {frag_size}\n{RESET}")

        elif mess_or_file_flag == 5:
            print(
                OKRED
                + r"Enter path to save file [  C:\Users\Laura\Documents\škola\3semester\PKS\project2\recieved_files  ]: "
                + RESET
            )
            file_path = input()

            file_path = os.path.join(file_path, file_name)
            data = b"".join(data)
            with open(file_path, "wb") as new_file:
                new_file.write(data)
            print(f"{OKCYAN}\nFile name: {file_name}")
            print(f"New file path: {file_path}\n")
            print(f"File size: {len(data)}")
            print(f"Number of fragments: {frag_count}")
            print(f"Fragment size: {frag_size}\n{RESET}")

    else:
        if mess_or_file_flag == 4:
            print(f"{OKYELLOW}\nMessage not received correctly.\n")
            print(f"{OKCYAN}Message size: {len(data)}")
            print(f"Number of fragments: {frag_count}")
            print(f"Number of correct fragments: {correct_received_fragments}")
            print(f"Fragment size: {frag_size}\n{RESET}")
        elif mess_or_file_flag == 5:
            print(f"{OKYELLOW}\nFile not received correctly.\n")
            print(f"{OKCYAN}File name: {file_name}")
            print(f"File size: {len(data)}")
            print(f"Number of fragments: {frag_count}")
            print(f"Number of correct fragments: {correct_received_fragments}")
            print(f"Fragment size: {frag_size}\n{RESET}")
