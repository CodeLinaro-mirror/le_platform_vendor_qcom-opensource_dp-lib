# dp_lib (CSM Data Path Driver Library)

## Overview
This repository contains a library component (`dp_lib`) for the `csm_dp` driver. It provides core functionalities, API definitions, and architectural specifics for the CSM data path.

### Block Diagram

```
+---------------------+       +-----------------+
|     User Space      |       |    User Space   |
|                     |       |                 |
| dp_ping/L2/MAC-e    +-----> |   dp_lib API    |
|                     |       |                 |
+---------------------+       +--------|--------+
                                       |
                           (Interacts via ioctl/mmap)
                                       |
                                       V
                       +-----------------------------+
                       |        Kernel Space         |
                       |                             |
                       |      qcom_csm_dp Driver     |
                       |                             |
                       +--------------|--------------+
                                      | Manages:
                                      | - Character Device /dev/csmX-dpY
                                      | - Memory/Buffers
                                      | - Debugfs Interface
                                      |
                                      | Interacts with:
                                      | - MHI Host Driver
                                      V
                       +-----------------------------+
                       |        Kernel Space         |
                       |                             |
                       |       MHI Host Driver       |
                       |                             |
                       +--------------|--------------+
                                      | Interacts with
                                      V
                       +-----------------------------+
                       |          Hardware           |
                       |                             |
                       |       QDU100 Device         |
                       |                             |
                       +-----------------------------+
```

## Build and Install
**Navigate to the dp-lib top directory:**


    $ cd <Work Space>/dp-lib
    $ make
    $ sudo make install
    $ sudo ldconfig

    # Optional build command
    $ cd <Work Space>/dp-lib/test/dp_ping/
    $ make
    $ sudo make install


## dp_ping utility Usage

The `dp_ping` utility is a testing application that uses the `dp_lib` to send and receive packets, measure latency, and report statistics.

## Usage:

    dp_ping <option>


### Options:

**TX Options:**
*   `-b <number>`: Number of packets in one burst (1..64), default 1.
*   `-c <packet counter>`: Packet counter, default infinite.
*   `-i <TX interval in us>`: TX interval in microseconds (fractional values >=0 allowed), default 1,000,000 (1 second).
*   `-l <TX packet length in bytes>`: TX packet length in bytes, default 1K, max ~2MB.
*   `-m`: Enable TX packet mirroring.
*   `-C`: Enable TX packet data capture.
*   `-G`: Send packet in scatter-gather mode.
*   `--buf_size <size>`: TX memory pool buffer size, default 2K bytes.
*   `--buf_count <count>`: TX memory pool buffer count, default 4096 buffers.
*   `--tx_affinity <core_num>`: Enable CPU affinity (1..number of available cores) for Tx thread.

**RX Options:**
*   `-t <timeout in ms>`: Timeout in milliseconds, default 2,000.
*   `--rx_poll_interval <interval in us>`: Rx poll interval in microseconds, relevant only with `-P` (polling mode), default 125.
*   `--rx_affinity <core_num>`: Enable CPU affinity (1..number of available cores) for Rx thread.

**REPORT Options:**
*   `-d <max pending result>`: Maximum pending result for the internal result FIFO.
*   `-p <period in seconds>`: Report period in seconds, default 10.
*   `-r <interval to report in ms>`: Interval to report in milliseconds.
*   `-s`: Use syslog for logging (instead of `printf`).
*   `-S`: Report TX status statistics.

**General Options:**
*   `-v`: Enable verbose logging.
*   `-x`: Enable checksum verification.
*   `-B <bus number>`: **Bus number, default 0.** Used to specify the bus number for the DP device (e.g., `/dev/csm<bus_num>-dp<vf_num>`).
*   `-D`: Obsolete, see `-V`.
*   `-L`: Print latency statistics for this report period.
*   `-P`: Polling mode (Tx/Rx over DATA channel).
*   `-R`: Fill packet payload from random number generator.
*   `-V <VF number>`: **Virtual function (VF0..3), default 0.** Used to specify the virtual function number for the DP device (e.g., `/dev/csm<bus_num>-dp<vf_num>`).

### Example Commands:

*   **Basic Ping (Control Channel):**
    ```bash
    dp_ping -l 1024 -c 100 -i 1000000
    ```
    Sends 100 packets of 1KB length with 1 second interval on the control channel.

*   **Data Channel Polling Mode with Latency Stats:**
    ```bash
    dp_ping -P -l 2048 -c 5000 -i 500 -L
    ```
    Sends 5000 packets of 2KB length every 500 microseconds on the data channel in polling mode, and reports latency statistics.

*   **With TX Affinity and Verification:**
    ```bash
    dp_ping -l 512 -x --tx_affinity 2
    ```
    Sends packets of 512 bytes with checksum verification, ensuring the TX thread runs on CPU core 2.

*   **Traffic Capture to File:**
    ```bash
    dp_ping -C -l 1024 -c 1000
    ```
    Sends 1000 packets and captures the traffic to `/tmp/dp_ping.pcap_VF<vf_num>`.

*   **Specifying Bus and VF Numbers:**
    ```bash
    dp_ping -B 1 -V 2 -l 1024 -c 10
    ```
    Initializes `dp_ping` to interact with the device `/dev/csm1-dp2`, sending 10 packets of 1KB length.

For specific integration and usage, refer to the main `csm_dp` driver documentation and source code, as well as any platform-specific documentation (e.g., for QDU100).

# License

Licensed under BSD-3-Clause-Clear
