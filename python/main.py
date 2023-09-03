import dataclasses
import io
import random
import struct
import typing

random.seed(1)

TYPE_A = 1
CLASS_IN = 1


@dataclasses.dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclasses.dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


@dataclasses.dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


@dataclasses.dataclass
class DNSPacket:
    header: DNSHeader
    questions: typing.List[DNSQuestion]
    answers: typing.List[DNSRecord]
    authorities: typing.List[DNSRecord]
    additionals: typing.List[DNSRecord]



def header_to_bytes(header: DNSHeader):
    fields = dataclasses.astuple(header)
    # 6 fields
    return struct.pack('!HHHHHH', *fields)


def question_to_bytes(question: DNSQuestion):
    return question.name + struct.pack("!HH", question.type_, question.class_)


def encode_dns_name(domain_name: str):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def build_query(domain_name: str, record_type: int):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    header = DNSHeader(id=id, num_questions=1, flags=0)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


def parse_header(reader: io.BytesIO):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def parse_question(reader: io.BytesIO):
    name = decode_name(reader)
    type_, class_ = struct.unpack("!HH", reader.read(4))
    return DNSQuestion(name, type_, class_)


def parse_record(reader: io.BytesIO):
    name = decode_name(reader)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", reader.read(10))
    data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


def parse_dns_packet(data: bytes):
    reader = io.BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def decode_name(reader: io.IOBase):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length: int, reader: io.IOBase):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def ip_to_string(ip: bytes):
    return ".".join([str(x) for x in ip])


def lookup_domain(domain_name: str):
    import socket

    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # get the response
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)


if __name__ == "__main__":
    import sys

    print(lookup_domain(domain_name=sys.argv[1]))
