import header as Header
import socket

# colors for printing
OKCYAN = "\033[96m"
OKYELLOW = "\033[93m"
RESET = "\033[0m"


def send_data(
    flag,
    fragment_size,
    num_fragments,
    server_address,
    client_socket,
    error_indexes,
    error_indexes2,
    whole_data,
    file_name,
    file_path,
):
    correct_received_fragments = 0

    data_list = []

    for i in range(num_fragments):
        data_list.append(whole_data[i * fragment_size : (i + 1) * fragment_size])

    for i in range(num_fragments):
        counter_of_retries = 0
        # get fragment from whole data by splitting it
        fragment = data_list[i]

        # send fragment with error in data
        if i % 2 == 1:
            mess = Header.create_header(
                flag, fragment_size, num_fragments, i, fragment, True
            )
            client_socket.sendto(mess, server_address)
            print(f"Fragment order: {i} of {num_fragments - 1} (EVEN, sent with error)")
        elif i in error_indexes:
            mess = Header.create_header(
                flag, fragment_size, num_fragments, i, fragment, True
            )
            client_socket.sendto(mess, server_address)
            print(f"Fragment order: {i} of {num_fragments - 1} (sent with error)")

        # don't send fragment
        elif i in error_indexes2:
            print(f"Fragment order: {i} of {num_fragments - 1} (not sent)")
            pass
        # send fragment without error in data
        else:
            mess = Header.create_header(
                flag, fragment_size, num_fragments, i, fragment, False
            )
            client_socket.sendto(mess, server_address)
            print(f"Fragment order: {i} of {num_fragments - 1} (sent correctly))")

        # wait for reply
        while True:
            client_socket.settimeout(0.5)
            try:
                # decode header
                reply, server_address = client_socket.recvfrom(1500)
                (
                    rec_flag,
                    _,
                    _,
                    _,
                    frag_order,
                    _,
                ) = Header.decode_header(reply)

                # check if flag is correct and if fragment order is correct and if it is, break
                if rec_flag == 6 and frag_order == i:
                    print("Fragment received correctly")
                    correct_received_fragments += 1
                    break

            except socket.timeout:
                # if fragment is not received correctly, try again
                print("Fragment not received correctly, trying again")
                counter_of_retries += 1
                fragment = whole_data[i * fragment_size : (i + 1) * fragment_size]

                mess = Header.create_header(
                    flag,
                    fragment_size,
                    num_fragments,
                    i,
                    fragment,
                    False,
                )
                client_socket.sendto(mess, server_address)
            # if there are too many retries, abort
            if counter_of_retries == 10:
                print("Too many retries, aborting")
                return

    # send last fragment that gives information about stop sending data
    ack_message = Header.create_header(
        6, fragment_size, num_fragments, 0, "wholemessack", False
    )
    client_socket.sendto(ack_message, server_address)

    # check if all fragments were received correctly and print information
    if correct_received_fragments == (num_fragments):
        print(OKYELLOW + "\nWhole message/file was successfully send and received")
        if flag == 4:
            print(f"{OKCYAN}\nMessage: {whole_data}\n")
            print(f"Message size: {len(whole_data)}")
            print(f"Number of fragments: {num_fragments}")
            print(f"Fragment size: {fragment_size}\n{RESET}")

        else:
            print(f"{OKCYAN}\nFile name: {file_name}")
            print(f"File path: {file_path}\n")
            print(f"File size: {len(whole_data)}")
            print(f"Number of fragments: {num_fragments}")
            print(f"Fragment size: {fragment_size}\n{RESET}")

        return True
    else:
        print(OKYELLOW + "\nMessage/file was not received correctly")
        if flag == 4:
            print(f"{OKCYAN}\nMessage: {whole_data}\n")
            print(f"Message size: {len(whole_data)}")
            print(f"Number of fragments: {num_fragments}")
            print(f"Number of correct fragments: {correct_received_fragments}")
            print(f"Fragment size: {fragment_size}\n{RESET}")

        else:
            print(f"{OKCYAN}\nFile name: {file_name}")
            print(f"File path: {file_path}\n")
            print(f"File size: {len(whole_data)}")
            print(f"Number of fragments: {num_fragments}")
            print(f"Number of correct fragments: {correct_received_fragments}")
            print(f"Fragment size: {fragment_size}\n{RESET}")

        return False
