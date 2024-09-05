/* pd-hidraw.c
 * By Lucas Cordiviola <lucarda27@hotmail.com> 2022
 * send message added by Ben Wesch 2024
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
#define HIDRAW_BUGFIX_VERSION 0

#define MAXHIDS 50
#define MAXSTR 255
#define BUFSIZE 256

typedef struct _hidraw {
    t_object x_obj;
    struct hid_device_info *devs;
    unsigned short targetPID;
    unsigned short targetVID;
    unsigned char buf[BUFSIZE];
    unsigned char *write_buf; // separate buffer for writing
    int write_size;
    int outReportID;
    int outReportSize;
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

static void print_device(struct hid_device_info *cur_dev)
{
    post("\n\n  type: %04hx %04hx\n  path: %s\n  serial_number: %ls", cur_dev->vendor_id, cur_dev->product_id, cur_dev->path, cur_dev->serial_number);
    post("  Manufacturer: %ls", cur_dev->manufacturer_string);
    post("  Product:      %ls", cur_dev->product_string);
    post("  Release:      %hx", cur_dev->release_number);
    post("  Interface:    %d",  cur_dev->interface_number);
    post("  Usage (page): 0x%hx (0x%hx)", cur_dev->usage, cur_dev->usage_page);
    post(" ");
}

static void print_devices(struct hid_device_info *cur_dev, t_hidraw *x)
{
    int i = 1; // start enumeration from 1 to use 0 as closedevice()

    while (cur_dev) {
        post("-----------\nPd device enum: %d", i);
        post("device VID PID (shown in decimal notation): %d %d", cur_dev->vendor_id,
            cur_dev->product_id);
        x->hidpath[i] = getbytes(strlen(cur_dev->path)+1);
        strcpy((char *)x->hidpath[i], cur_dev->path);
        x->ndevices = i;
        i++;
        print_device(cur_dev);
        cur_dev = cur_dev->next;
    }
}

static void hidraw_parse_descriptor(t_hidraw *x)
{
    if (!x->handle) {
        pd_error(x, "hidraw: no device opened yet");
        return;
    }

    // candidate values
    int outReportID = 0;
    int outReportSize = 0;

    x->readlen = hid_get_report_descriptor(x->handle, x->buf, sizeof(x->buf));
    if (x->readlen > 0) {
        for (int i=0; i < x->readlen-1; i++){
            // based on https://eleccelerator.com/usbdescreqparser/
            if (x->buf[i] == 0x85) outReportID = x->buf[i+1]; // following byte is report id
            if (x->buf[i] == 0x95) outReportSize = x->buf[i+1]; // following byte is report size
            if (x->buf[i] == 0x91) { // use first detected output report definition
                x->outReportID = outReportID;
                x->outReportSize = outReportSize;
                post("hidraw: suspected output report id: %d, length: %d", x->outReportID, x->outReportSize);
                return;
            }
        }
        pd_error(x, "hidraw: no output report definition found″");
    } else {
        pd_error(x, "hidraw: can't get descriptor: %ls", hid_error(x->handle));
    }
}

static void hidraw_open(t_hidraw *x, char openmode)
{
    if (x->handle){
        hid_close(x->handle);
        x->handle = NULL;
        post("hidraw: closing previously opened device ...");
    }

    if (openmode) {
        // Open the device using the VID, PID,
        // and optionally the Serial number.
        x->handle = hid_open(x->targetVID, x->targetPID, NULL);
    } else {
        // Open the device using the path
        x->handle = hid_open_path(x->targetpath);
    }

    if (!x->handle) {
        pd_error(x, "hidraw: unable to open device: %ls", hid_error(x->handle));
        x->handle = NULL;
        return;
    }

    // Read the Product String
    x->wstr[0] = 0x0000;
    x->readlen = hid_get_product_string(x->handle, x->wstr, MAXSTR);
    if (x->readlen >= 0) post("hidraw: successfully opened device: %ls", x->wstr);
    else post("hidraw: successfully opened nameless device");

    // Set the hid_read() function to be non-blocking.
    hid_set_nonblocking(x->handle, 1);
    hidraw_parse_descriptor(x);

    // // Set up buffers.
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
    } else if (!x->devlistdone) {
        pd_error(x, "hidraw: devices not listed yet.");
        return;
    } else if (n > x->ndevices) {
        pd_error(x, "hidraw: device out range. current count of devices is: %d", x->ndevices);
        return;
    } else {
        x->targetpath = (char *)x->hidpath[n];
        hidraw_open(x, 0);
    }
}

static void hidraw_opendevice_vidpid(t_hidraw *x, t_float vid, t_float pid)
{
    x->targetVID = (unsigned short) vid;
    x->targetPID = (unsigned short) pid;
    hidraw_open(x, 1);
}

static void hidraw_listhids(t_hidraw *x)
{
    x->devs = hid_enumerate(0x0, 0x0);
    print_devices(x->devs, x);
    hid_free_enumeration(x->devs);
    x->devlistdone = 1;
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
    if (res < 0) {
        pd_error(x, "hidraw: unable to write: %ls", hid_error(x->handle));
    }

    freebytes(x->write_buf, x->write_size);
    x->write_buf = NULL;
    x->write_size = 0;
}

static void hidraw_write(t_hidraw *x, t_symbol *s, int ac, t_atom *av) {
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

    for (int i = 0; i < ac; i++) {
        write_buf[i] = (unsigned char)atom_getint(av + i);
    }

    x->write_buf = write_buf;
    x->write_size = ac;

    clock_delay(x->write_clock, 0);

    (void)s;
}

static void hidraw_describe(t_hidraw *x)
{
    t_atom out[BUFSIZE];

    if (!x->handle) {
        pd_error(x, "hidraw: no device opened yet");
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

static int hidraw_read(t_hidraw *x)
{
    t_atom out[BUFSIZE];

    if (!x->handle){
        pd_error(x, "hidraw: no device opened yet");
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
    post("---");
    post("  hidraw v%d.%d.%d", HIDRAW_MAJOR_VERSION, HIDRAW_MINOR_VERSION, HIDRAW_BUGFIX_VERSION);
    post("  hidapi v%d.%d.%d", HID_API_VERSION_MAJOR, HID_API_VERSION_MINOR, HID_API_VERSION_PATCH);
    post("---");
}

static void hidraw_free(t_hidraw *x) {

    if (x->handle){
        hid_close(x->handle);
    }
    if (x->write_buf) {
        freebytes(x->write_buf, x->write_size);
    }

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
    class_addmethod(hidraw_class, (t_method)hidraw_opendevice, gensym("open"), A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_opendevice_vidpid, gensym("open-vidpid"), A_FLOAT, A_FLOAT, 0);
    class_addmethod(hidraw_class, (t_method)hidraw_write, gensym("write"), A_GIMME, 0);
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
