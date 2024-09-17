/* pd-hidraw.c
 * By Lucas Cordiviola <lucarda27@hotmail.com> 2022
 * write mechanisms added by Ben Wesch 2024
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "m_pd.h"
#include <hidapi.h>


// Headers needed for sleeping.
#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif


// Sample using platform-specific headers
#if defined(__APPLE__)
#include <hidapi_darwin.h>
#endif

#if defined(_WIN32)
#include <hidapi_winapi.h>
#endif

#define HIDRAW_MAJOR_VERSION 0
#define HIDRAW_MINOR_VERSION 2
#define HIDRAW_BUGFIX_VERSION 1

#define MAXHIDS 50
#define MAXSTR 255
#define BUFSIZE 256

typedef struct _hidraw {
    t_object x_obj;
    struct hid_device_info *devs;
    unsigned short target_pid;
    unsigned short target_vid;
    unsigned char buf[BUFSIZE];
    unsigned char *write_buf; // separate buffer for writing
    int write_size;
    int out_report_id;
    int out_report_size;
    wchar_t wstr[MAXSTR];
    char *hidpath[MAXHIDS];
    char *targetpath;
    int readlen;
    char devlistdone;
    int ndevices;
    t_float polltime;
    hid_device *handle;
    t_outlet *bytes_out, *readstatus;
    t_clock *hidclock;
    t_clock *write_clock; // clock for write scheduling
} t_hidraw;

t_class *hidraw_class;

static void hidraw_device_info(t_hidraw *x, t_float id)
{
    int device_id = (int)id;

    if (device_id < 1 || device_id > x->ndevices) {
        post("hidraw: invalid device ID. Please provide a valid ID from the list.");
        return;
    }

    struct hid_device_info *cur_dev;
    cur_dev = x->devs;
    int i = 1;

    while (cur_dev && i < device_id) {
        cur_dev = cur_dev->next;
        i++;
    }

    if (!cur_dev) {
        post("hidraw: unable to find device %d", device_id);
        return;
    }

    post("\nDetailed information for device %d:", device_id);
    post("    VendorID ProductID: %04hx %04hx", cur_dev->vendor_id, cur_dev->product_id);
    post("    Path:               %s", cur_dev->path);
    post("    Serial Number:      %ls", cur_dev->serial_number);
    post("    Manufacturer:       %ls", cur_dev->manufacturer_string);
    post("    Product:            %ls", cur_dev->product_string);
    post("    Release:            %hx", cur_dev->release_number);
    post("    Interface:          %d", cur_dev->interface_number);
    post("    Usage:              0x%hx", cur_dev->usage);
    post("    Usage Page:         0x%hx\n", cur_dev->usage_page);
}

static void hidraw_listhids(t_hidraw *x)
{
    struct hid_device_info *cur_dev;
    int i = 1; // start enumeration from 1

    x->devs = hid_enumerate(0x0, 0x0);
    if (!x->devs) {
        post("hidraw: no HID devices available.");
        return;
    }

    cur_dev = x->devs;

    post("\nhidraw: enumerated HID devices:");
    while (cur_dev) {
        x->hidpath[i - 1] = getbytes(strlen(cur_dev->path) + 1);
        if (x->hidpath[i - 1] == NULL) {
            post("hidraw: failed to allocate memory for device path.");
            hid_free_enumeration(x->devs);
            return;
        }

        strcpy((char *)x->hidpath[i - 1], cur_dev->path);

        wchar_t *manufacturer = (cur_dev->manufacturer_string && wcslen(cur_dev->manufacturer_string) > 0) ? cur_dev->manufacturer_string : L"n/a";
        wchar_t *product = (cur_dev->product_string && wcslen(cur_dev->product_string) > 0) ? cur_dev->product_string : L"n/a";

        if (cur_dev->vendor_id == 0 && cur_dev->product_id == 0) {
            post("    %2d: %ls %ls", i, manufacturer, product);
        } else {
            post("    %2d: %ls %ls - VID PID: %d %d", i, manufacturer, product, cur_dev->vendor_id, cur_dev->product_id);
        }

        cur_dev = cur_dev->next;
        x->ndevices = i;

        if (++i > MAXHIDS) {
            post("hidraw: maximum number of HID devices (%d) reached. Some devices may not be listed.", x->ndevices);
            break;
        }
    }

    x->devlistdone = 1;
}

static void hidraw_parse_descriptor(t_hidraw *x)
{
    if (!x->handle) {
        pd_error(x, "hidraw: no device opened yet");
        return;
    }

    // candidate values
    int out_report_id = 0;
    int out_report_size = 0;

    x->readlen = hid_get_report_descriptor(x->handle, x->buf, sizeof(x->buf));
    if (x->readlen > 0) {
        for (int i=0; i < x->readlen-1; i++){
            // based on https://eleccelerator.com/usbdescreqparser/
            if (x->buf[i] == 0x85) out_report_id = x->buf[i+1]; // following byte is report id
            if (x->buf[i] == 0x95) out_report_size = x->buf[i+1]; // following byte is report size
            if (x->buf[i] == 0x91) { // use first detected output report definition
                x->out_report_id = out_report_id;
                x->out_report_size = out_report_size + 1; // adding 1 to consider report id
                post("hidraw: suspected specs for writing output reports: id %d, size %d (with id)", x->out_report_id, x->out_report_size);
                return;
            }
        }
        post("hidraw: no output report definition found");
    } else {
        pd_error(x, "hidraw: can't get descriptor: %ls", hid_error(x->handle));
    }
}

static void hidraw_open(t_hidraw *x, char openmode)
{
    if (x->handle){
        hid_close(x->handle);
        x->handle = NULL;
        post("hidraw: closed previously opened device");
    }

    if (openmode) {
        x->handle = hid_open(x->target_vid, x->target_pid, NULL); // open using VID, PID
    } else {
        x->handle = hid_open_path(x->targetpath); // open using path through enum
    }

    if (!x->handle) {
        pd_error(x, "hidraw: unable to open device: %ls", hid_error(x->handle));
        x->handle = NULL;
        return;
    }

    // read the product string
    x->wstr[0] = 0x0000;
    x->readlen = hid_get_product_string(x->handle, x->wstr, MAXSTR);

    if (x->wstr[0] > 0) {
        post("hidraw: successfully opened device: %ls", x->wstr);
    } else {
        post("hidraw: successfully opened device");
    }

    // set the hid_read() function to be non-blocking.
    hid_set_nonblocking(x->handle, 1);
    hidraw_parse_descriptor(x);

    // // set up buffers.
    // memset(x->buf,0x00,sizeof(x->buf));
}

static void hidraw_closedevice(t_hidraw *x)
{
    if (x->handle) {
        hid_close(x->handle);
        x->handle = NULL;
        post("hidraw: device closed");
    }
}

static void hidraw_opendevice(t_hidraw *x, t_float hidn)
{
    int n = (int)hidn;

    if (n == 0) {
        hidraw_closedevice(x);
        return;
    } else if (n > x->ndevices) {
        pd_error(x, "hidraw: device out range. current count of devices is: %d", x->ndevices);
        return;
    } else if (!x->devlistdone) {
        pd_error(x, "hidraw: devices not listed yet");
        return;
    }
    x->targetpath = (char *)x->hidpath[n-1];
    hidraw_open(x, 0);
}

static void hidraw_opendevice_vidpid(t_hidraw *x, t_float vid, t_float pid)
{
    x->target_vid = (unsigned short) vid;
    x->target_pid = (unsigned short) pid;
    hidraw_open(x, 1);
}

static void hidraw_poll(t_hidraw *x, t_float f )
{
    x->polltime = f;
    if (f > 0) clock_delay(x->hidclock, 0);
    else clock_unset(x->hidclock);
}

// performs actual HID write, called by clock
static void hidraw_do_write(t_hidraw *x) {
    if (!x->handle) {
        pd_error(x, "hidraw: no device opened yet");
        return;
    }

    int res = hid_send_output_report(x->handle, x->write_buf, x->write_size);
    if (res < 0) pd_error(x, "hidraw: unable to write: %ls", hid_error(x->handle));

    freebytes(x->write_buf, x->write_size);
    x->write_buf = NULL;
    x->write_size = 0;
}

static inline void hidraw_write(t_hidraw *x, t_symbol *s, int ac, t_atom *av) {
    if (!x->handle) {
        pd_error(x, "hidraw: no device opened yet");
        return;
    }

    // allocate buffer for write data
    unsigned char *write_buf = (unsigned char *)getbytes(ac * sizeof(unsigned char));
    if (!write_buf) {
        pd_error(x, "hidraw: memory allocation failed for write buffer");
        return;
    }

    for (int i = 0; i < ac; i++) write_buf[i] = (unsigned char)atom_getint(av + i);
    x->write_buf = write_buf;
    x->write_size = ac;

    clock_delay(x->write_clock, 0);

    (void)s;
}

static void hidraw_writesafe(t_hidraw *x, t_symbol *s, int ac, t_atom *av) {
    if (ac != x->out_report_size) {
        pd_error(x, "hidraw: report size doesn't match. expected %d, received %d", x->out_report_size, ac);
        return;
    }
    
    int id = atom_getint(av);
    if (id != x->out_report_id) {
        pd_error(x, "hidraw: report ID doesn't match. expected %d, received %d", x->out_report_id, id);
        return;
    }

    hidraw_write(x, s, ac, av);
}

static void hidraw_describe(t_hidraw *x)
{
    t_atom out[BUFSIZE];

    if (!x->handle) {
        pd_error(x, "hidraw: can't read descriptor: no device opened yet");
        return;
    }

    x->readlen = hid_get_report_descriptor(x->handle, x->buf, sizeof(x->buf));

    if (x->readlen > 0) { // success
        for(int i = 0; i < x->readlen; i++) SETFLOAT(out+i, x->buf[i]);
        outlet_list(x->bytes_out, NULL, x->readlen, out);
    } else { // error
        pd_error(x, "hidraw: can't get descriptor: %ls", hid_error(x->handle));
    }
}

static inline int hidraw_read(t_hidraw *x)
{
    t_atom out[BUFSIZE];

    if (!x->handle){
        pd_error(x, "hidraw: can't read: no device opened yet");
        return 0;
    }

    int readlen_last = x->readlen;
    x->readlen = hid_read(x->handle, x->buf, sizeof(x->buf));

    if (x->readlen > 0) { // success
        for(int i = 0; i < x->readlen; i++) SETFLOAT(out+i, x->buf[i]);
        outlet_float(x->readstatus, 2);
        outlet_list(x->bytes_out, NULL, x->readlen, out);
    } else if (x->readlen == 0) { // waiting...
        outlet_float(x->readstatus, 1);
    } else { // error
        if (readlen_last >= 0) pd_error(x, "hidraw: can't read: %ls. still polling ...", hid_error(x->handle));
        outlet_float(x->readstatus, -1);
    }
    return 1;
}

static void hidraw_tick(t_hidraw *x)
{
    if (hidraw_read(x))
        clock_delay(x->hidclock, x->polltime);
}

static void hidraw_pdversion(void)
{
    post("\n  hidraw v%d.%d.%d", HIDRAW_MAJOR_VERSION, HIDRAW_MINOR_VERSION, HIDRAW_BUGFIX_VERSION);
    post(  "  hidapi v%d.%d.%d\n", HID_API_VERSION_MAJOR, HID_API_VERSION_MINOR, HID_API_VERSION_PATCH);
}

static void hidraw_free(t_hidraw *x) {

    if (x->handle) hid_close(x->handle);
    if (x->write_buf) freebytes(x->write_buf, x->write_size);

    hid_free_enumeration(x->devs);
    clock_free(x->hidclock);
    clock_free(x->write_clock);
    hid_exit();
}

// this is commented out because it is incompatible with not so old Pds
/*

static void hidraw_cleanup(t_class *c) {

    //Free static HIDAPI objects. (when Pd shuts down.)
    hid_exit();

}
*/

static void *hidraw_new(void)
{
    t_hidraw *x = (t_hidraw *)pd_new(hidraw_class);

    x->hidclock = clock_new(x, (t_method)hidraw_tick);
    x->write_clock = clock_new(x, (t_method)hidraw_do_write);

    x->bytes_out = outlet_new(&x->x_obj, &s_list);
    x->readstatus = outlet_new(&x->x_obj, &s_float);

    x->ndevices = 0;
    x->devlistdone = 0;
    x->handle = NULL;
    x->write_buf = NULL;
    x->write_size = 0;
    x->targetpath = getbytes(256);

    return (void *)x;
}

#if defined(_WIN32)
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
void hidraw_setup(void)
{
    hidraw_class = class_new(gensym("hidraw"),
                   (t_newmethod)hidraw_new,
                   (t_method)hidraw_free,
                   sizeof(t_hidraw),
                   CLASS_DEFAULT,
                   0);

    //class_setfreefn(hidraw_class, hidraw_cleanup); // I prefer to not do this as it is incompatible with not so old Pds.
    class_addbang(hidraw_class, hidraw_read);
    class_addmethod(hidraw_class, (t_method)hidraw_read, gensym("read"), 0);
    class_addmethod(hidraw_class, (t_method)hidraw_listhids, gensym("listdevices"), 0);
    class_addmethod(hidraw_class, (t_method)hidraw_listhids, gensym("scan"), 0);
    class_addmethod(hidraw_class, (t_method)hidraw_device_info, gensym("info"), A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_opendevice, gensym("open"), A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_opendevice_vidpid, gensym("open-vidpid"), A_FLOAT, A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_writesafe, gensym("write"), A_GIMME, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_write, gensym("writeunsafe"), A_GIMME, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_describe, gensym("describe"), 0);
    class_addmethod(hidraw_class, (t_method)hidraw_poll, gensym("poll"), A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_closedevice, gensym("close"), 0);

    hidraw_pdversion();
    hid_init();

#if defined(__APPLE__)
    // To work properly needs to be called before hid_open/hid_open_path after hid_init.
    // Best/recommended option - call it right after hid_init.
    hid_darwin_set_open_exclusive(0);
#endif
}
