import dataclasses
import struct


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
