#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/uio.h>
#include <linux/types.h>

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *)1;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) =
    (void *)2;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *)14;

struct map_t
{
    u32 map_type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
};

struct map_t __test_map __attribute__((section("maps/test_map"), used)) = {
    BPF_MAP_TYPE_ARRAY,
    sizeof(u32),
    sizeof(u32),
    1024};

__attribute__((section("kprobe/test_program"), used)) int test_program(struct pt_regs *regs)
{
    (void)bpf_get_current_pid_tgid();
    return 0;
}

__attribute__((section("kprobe/test_program_map_update"), used)) int test_program_map_update(struct pt_regs *regs)
{
    u32 index = 0;
    u32 *value = bpf_map_lookup_elem(&__test_map, &index);
    if (!value)
    {
        u32 new_value = 1;
        bpf_map_update_elem(&__test_map, &index, &new_value, BPF_ANY);
    }
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "Proprietary";
uint32_t _version __attribute__((section("version"), used)) = 0xFFFFFFFE;