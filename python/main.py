import dataclasses
import io
import random
import struct

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
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


def parse_header(reader: io.BytesIO):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def parse_question(reader: io.BytesIO):
    name = decode_name_simple(reader)
    type_, class_ = struct.unpack("!HH", reader.read(4))
    return DNSQuestion(name, type_, class_)


def decode_name_simple(reader: io.IOBase):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)


def main():
    import socket

    query = build_query("www.example.com", 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    response, _ = sock.recvfrom(1024)
    reader = io.BytesIO(response)
    print(parse_header(reader))
    print(parse_question(reader))


if __name__ == "__main__":
    main()
