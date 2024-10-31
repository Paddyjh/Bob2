# Bob2

Created for the management of a protocol for Scalable Computing 2024. This should be entirely collaborative, and the initial version is mostly built as a jumping off point for the class (or whoever decides to use Bob2 as their protocol).

## Protocol Summary

| Byte 0                           | Byte 1                           | Byte 2                           | Bytes 3-18   | Bytes 19-20 | Bytes 21-25                                                                            | Bytes 26+ |
| -------------------------------- | -------------------------------- | -------------------------------- | ------------ | ----------- | -------------------------------------------------------------------------------------- | --------- |
| Bob2 major version - EG 1 in 1.0 | Bob2 minor version - EG 0 in 1.0 | Message Type - more detail below | Destination IPv6 Address | Destination Port number | Length of message in bytes (allows up to a terabyte of data to be sent in one message) |  Message         |
|                                  |                                  |                                  |              |             |                                                                                        |           |

Message types - up to 256 types in Bob2 v0.0.

| Value of Byte 32 | Message type                             |
| ---------------- | ---------------------------------------- |
| 0                | Sending Message           |
| 1                | ACK |

## Protocol Requirements

1. Bob2 Version - format X.X
2. Contain message type 
    1. Sending to ground station
    2. ACK returning from ground station
3. Describe message length in bytes
4. Contain message destination - IPv6?
5. Message content bytes!

## Protocol Details

Bob2 v0.0 has the following assumptions, based on the simplest understanding of a LEO system

1. The network is built up of 3 component types
    1. Earth node - in a standard use case, this is a Starlink (or similar) customer with a satellite to connect to the LEO satellites.
    2. Satellites - in all cases, these are the actual Low Earth Orbit satellites. In this assignment, these are what are represented by the raspberry pis. They receive messages from source nodes, which are passed between satellites until they can find the destination node.
2. Any simulated delays/lags/latency/jitter (to recreate an LEO system) is handled by the code sending/receiving messages, and is not handled within the protocol.
3. We shouldn't get more than 256.256 versions of Bob2 (I'm hoping)
4. Retries are also handled outside of the protocol, making use of the ACK within the protocol (feel free to add more sections to handle this).
5. Routing between satellites (ISL) is handled outside of the protocol.


## Potential Areas for improvement

1. Checksum to check for message corruption.
2. Encrypting the message.


