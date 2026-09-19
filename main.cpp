/*
Copyright (C) 2026 Mohamed A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>

// im lazy
using namespace std;

static constexpr uint64_t RAM_BASE = 0x40000000ULL;
static constexpr uint64_t RAM_SIZE = 512ULL * 1024ULL * 1024ULL;

static constexpr uint64_t KERNEL_OFFSET = 0x00080000ULL;
static constexpr uint64_t KERNEL_BASE = RAM_BASE + KERNEL_OFFSET;

static constexpr uint64_t DTB_BASE = RAM_BASE + 0x01000000ULL;
static constexpr uint64_t INITRD_BASE = RAM_BASE + 0x08000000ULL;

static constexpr uint64_t UART_BASE = 0x09000000ULL;

static void Error(const char* message)
{
    fprintf(stderr, "%s: %s\n", message, strerror(errno));
    exit(1);
}

static int OpenKVM()
{
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

    if (fd < 0)
        Error("open /dev/kvm");

    int api = ioctl(fd, KVM_GET_API_VERSION, 0);

    if (api != KVM_API_VERSION)
    {
        fprintf(stderr, "Invalid KVM API version: %d\n", api);
        exit(1);
    }

    return fd;
}

static int CreateVM(int kvm)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);

    if (vm < 0)
        Error("KVM_CREATE_VM");

    return vm;
}

static void* CreateGuestMemory(int vm)
{
    void* memory = mmap(nullptr, RAM_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0);

    if (memory == MAP_FAILED)
        Error("mmap guest RAM");

    memset(memory, 0, RAM_SIZE);

    kvm_userspace_memory_region region{};

    region.slot = 0;
    region.guest_phys_addr = RAM_BASE;
    region.memory_size = RAM_SIZE;
    region.userspace_addr = reinterpret_cast<uint64_t>(memory);

    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) < 0)
        Error("KVM_SET_USER_MEMORY_REGION");

    return memory;
}

static void CreateGIC(int vm)
{
    if (ioctl(vm, KVM_CREATE_IRQCHIP, 0) < 0)
        Error("KVM_CREATE_IRQCHIP");
}

static int CreateVCPU(int vm, size_t* mmap_size)
{
    int size = ioctl(vm, KVM_GET_VCPU_MMAP_SIZE, 0);

    if (size < 0)
        Error("KVM_GET_VCPU_MMAP_SIZE");

    int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);

    if (vcpu < 0)
        Error("KVM_CREATE_VCPU");

    *mmap_size = static_cast<size_t>(size);

    return vcpu;
}

static void InitVCPU(int vm, int vcpu)
{
    kvm_vcpu_init init{};

    if (ioctl(vm, KVM_ARM_PREFERRED_TARGET, &init) < 0)
        Error("KVM_ARM_PREFERRED_TARGET");

    if (ioctl(vcpu, KVM_ARM_VCPU_INIT, &init) < 0)
        Error("KVM_ARM_VCPU_INIT");
}

static void SetRegister(int vcpu, uint64_t id, uint64_t value)
{
    kvm_one_reg reg{};

    reg.id = id;
    reg.addr = reinterpret_cast<uint64_t>(&value);

    if (ioctl(vcpu, KVM_SET_ONE_REG, &reg) < 0)
        Error("KVM_SET_ONE_REG");
}

static uint64_t CoreRegister(uint64_t reg)
{
    return KVM_ARM64_CORE_REG(
        KVM_REG_ARM64,
        KVM_REG_SIZE_U64,
        reg
    );
}

static void SetupRegisters(int vcpu)
{
    uint64_t pc = KERNEL_BASE;
    uint64_t sp = RAM_BASE + RAM_SIZE - 0x1000;

    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(sp)), sp);
    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(pc)), pc);

    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(regs.regs[0])), DTB_BASE);
    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(regs.regs[1])), 0);
    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(regs.regs[2])), 0);
    SetRegister(vcpu, CoreRegister(KVM_ARM64_CORE_REG(regs.regs[3])), 0);
}

static size_t LoadFile(void* memory, uint64_t guest_address, const char* filename)
{
    int fd = open(filename, O_RDONLY);

    if (fd < 0)
        Error(filename);

    if (lseek(fd, 0, SEEK_END) < 0)
        Error("lseek");

    off_t size = lseek(fd, 0, SEEK_CUR);

    if (size < 0)
        Error("lseek");

    if (lseek(fd, 0, SEEK_SET) < 0)
        Error("lseek");

    uint64_t offset = guest_address - RAM_BASE;

    if (offset + static_cast<uint64_t>(size) > RAM_SIZE)
    {
        fprintf(stderr, "File is too large: %s\n", filename);
        close(fd);
        exit(1);
    }

    char* destination = static_cast<char*>(memory) + offset;

    size_t total = 0;

    while (total < static_cast<size_t>(size))
    {
        ssize_t result = read(
            fd,
            destination + total,
            static_cast<size_t>(size) - total
        );

        if (result <= 0)
            Error("read");

        total += static_cast<size_t>(result);
    }

    close(fd);

    printf("Loaded %-20s 0x%08llx (%zu bytes)\n",
        filename,
        static_cast<unsigned long long>(guest_address),
        total);

    return total;
}

static void CheckKernel(void* memory)
{
    uint64_t offset = KERNEL_BASE - RAM_BASE;
    uint8_t* kernel = static_cast<uint8_t*>(memory) + offset;

    uint32_t magic = 0;

    memcpy(&magic, kernel + 56, sizeof(magic));

    if (magic != 0x644d5241)
    {
        fprintf(stderr, "Not an ARM64 Linux Image\n");
        fprintf(stderr, "Magic: 0x%08x\n", magic);
        exit(1);
    }

    uint32_t text_offset = 0;

    memcpy(&text_offset, kernel + 8, sizeof(text_offset));

    printf("Kernel text offset: 0x%x\n", text_offset);
}

static uint32_t UARTRead(uint64_t address)
{
    uint64_t offset = address - UART_BASE;

    if (offset == 0x018)
        return 0x00000090;

    if (offset == 0x004)
        return 0;

    if (offset >= 0xFE0)
    {
        switch (offset)
        {
        case 0xFE0: return 0x11;
        case 0xFE4: return 0x10;
        case 0xFE8: return 0x14;
        case 0xFEC: return 0x00;

        case 0xFF0: return 0x0D;
        case 0xFF4: return 0xF0;
        case 0xFF8: return 0x05;
        case 0xFFC: return 0xB1;
        }
    }

    return 0;
}

static void UARTWrite(uint64_t address, const uint8_t* data, uint32_t length)
{
    uint64_t offset = address - UART_BASE;

    if (offset == 0x000 && length >= 1)
    {
        putchar(data[0]);
        fflush(stdout);
    }
}

static bool HandleMMIO(kvm_run* run)
{
    uint64_t address = run->mmio.phys_addr;

    if (address < UART_BASE || address >= UART_BASE + 0x1000)
        return false;

    if (run->mmio.is_write)
    {
        UARTWrite(
            address,
            run->mmio.data,
            run->mmio.len
        );
    }
    else
    {
        uint32_t value = UARTRead(address);

        memcpy(
            run->mmio.data,
            &value,
            run->mmio.len
        );
    }

    return true;
}

static void PrintExit(kvm_run* run)
{
    switch (run->exit_reason)
    {
    case KVM_EXIT_MMIO:
        printf("\nKVM_EXIT_MMIO\n");
        break;

    case KVM_EXIT_HLT:
        printf("\nKVM_EXIT_HLT\n");
        break;

    case KVM_EXIT_SHUTDOWN:
        printf("\nKVM_EXIT_SHUTDOWN\n");
        break;

    case KVM_EXIT_SYSTEM_EVENT:
        printf("\nKVM_EXIT_SYSTEM_EVENT\n");
        break;

    default:
        printf(
            "\nUnhandled KVM exit: %u\n",
            run->exit_reason
        );
        break;
    }
}

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        printf("Usage:\n");
        printf("  %s vmlinuz-virt initramfs-virt virt.dtb\n", argv[0]);
        return 1;
    }

    int kvm = OpenKVM();

    printf("KVM opened\n");

    int vm = CreateVM(kvm);

    printf("VM created\n");

    void* memory = CreateGuestMemory(vm);

    printf(
        "Guest RAM: 512 MiB at 0x%llx\n",
        static_cast<unsigned long long>(RAM_BASE)
    );

    CreateGIC(vm);

    printf("GICv2 created\n");

    size_t kernel_size = LoadFile(
        memory,
        KERNEL_BASE,
        argv[1]
    );

    CheckKernel(memory);

    size_t initrd_size = LoadFile(
        memory,
        INITRD_BASE,
        argv[2]
    );

    size_t dtb_size = LoadFile(
        memory,
        DTB_BASE,
        argv[3]
    );

    if (dtb_size > 2 * 1024 * 1024)
    {
        fprintf(stderr, "DTB is too large\n");
        return 1;
    }

    printf(
        "Kernel: %zu bytes\n"
        "Initramfs: %zu bytes\n"
        "DTB: %zu bytes\n",
        kernel_size,
        initrd_size,
        dtb_size
    );

    size_t mmap_size = 0;

    int vcpu = CreateVCPU(vm, &mmap_size);

    InitVCPU(vm, vcpu);

    void* run_area = mmap(
        nullptr,
        mmap_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        vcpu,
        0
    );

    if (run_area == MAP_FAILED)
        Error("mmap KVM run area");

    SetupRegisters(vcpu);

    printf("Starting ARM64 Linux...\n");
    printf("----------------------------------------\n");

    while (true)
    {
        int result = ioctl(vcpu, KVM_RUN, 0);

        if (result < 0)
        {
            if (errno == EINTR)
                continue;

            Error("KVM_RUN");
        }

        kvm_run* run = static_cast<kvm_run*>(run_area);

        if (run->exit_reason == KVM_EXIT_MMIO)
        {
            if (!HandleMMIO(run))
            {
                PrintExit(run);
                break;
            }

            continue;
        }

        PrintExit(run);

        if (run->exit_reason == KVM_EXIT_HLT)
            break;

        if (run->exit_reason == KVM_EXIT_SHUTDOWN)
            break;

        if (run->exit_reason == KVM_EXIT_SYSTEM_EVENT)
            break;

        break;
    }

    munmap(run_area, mmap_size);
    close(vcpu);
    munmap(memory, RAM_SIZE);
    close(vm);
    close(kvm);

    return 0;
}