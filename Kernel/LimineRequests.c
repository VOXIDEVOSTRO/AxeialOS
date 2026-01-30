
#include <LimineServices.h>

#define __Revision 0

__attribute__((used, section(".requests"))) volatile struct limine_hhdm_request HhdmRequest = {
    .id = LIMINE_HHDM_REQUEST, .revision = __Revision};

__attribute__((used, section(".requests"))) volatile struct limine_memmap_request MemmapRequest = {
    .id = LIMINE_MEMMAP_REQUEST, .revision = __Revision};

__attribute__((
    used,
    section(".requests"))) volatile struct limine_framebuffer_request EarlyLimineFrambuffer = {

    .id = LIMINE_FRAMEBUFFER_REQUEST, .revision = __Revision

};

__attribute__((used, section(".requests"))) volatile struct limine_rsdp_request EarlyLimineRsdp = {
    .id = LIMINE_RSDP_REQUEST, .revision = __Revision};

__attribute__((used, section(".requests"))) volatile struct limine_smp_request EarlyLimineSmp = {
    .id = LIMINE_SMP_REQUEST, .revision = __Revision};

__attribute__((used, section(".requests"))) volatile struct limine_module_request LimineMod = {
    .id = LIMINE_MODULE_REQUEST, .revision = __Revision};