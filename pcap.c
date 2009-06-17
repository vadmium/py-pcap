/**
    py-pcap: pcap file module for Python
    Copyright (C) 2007 Neale Pickett

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see
    <http://www.gnu.org/licenses/>.
 **/

#include <Python.h>
#include "obj.h"

/* Define some types (Windows doesn't have stdint.h).  Let's hope
   everything uses an 8-bit byte. */
#if SIZEOF_LONG == 4
typedef unsigned long _uint32_t;
typedef long _int32_t;
#elif SIZEOF_INT == 4
typedef unsigned int _uint32_t;
typedef int _int32_t;
#else
#  error "What's uint32 on this system?"
#endif

#if SIZEOF_INT == 2
typedef unsigned int _uint16_t;
typedef int _int16_t;
#elif SIZEOF_SHORT == 2
typedef unsigned short _uint16_t;
typedef short _int16_t;
#else
#  error "What's uint16 on this system?"
#endif


/* We only need two data structures from pcap.h.  We do the rest
   ourselves. */

struct pcap_file_header {
  _uint32_t magic;
  _uint16_t version_major;
  _uint16_t version_minor;
  _int32_t  thiszone;            /* gmt to local correction */
  _uint32_t sigfigs;             /* accuracy of timestamps */
  _int32_t  snaplen;             /* max length saved portion of each pkt */
  _int32_t  linktype;            /* data link type (LINKTYPE_*) */
};

/* So things still work on 64-bit CPUs.
   Note that this makes the program not Y2038-safe!
  */
struct pcap_timeval {
  _uint32_t tv_sec;
  _uint32_t tv_usec;
};

struct pcap_pkthdr {
  struct pcap_timeval ts;       /* time stamp */
  _uint32_t            caplen;   /* length of portion present */
  _uint32_t            len;      /* length this packet (off wire) */
};


/* Endian swap for 32-bit ints */
#define btoll(i) (((i & 0xff000000) >> 030) | \
                  ((i & 0x00ff0000) >> 010) | \
                  ((i & 0x0000ff00) << 010) | \
                  ((i & 0x000000ff) << 030))
#define btols(i) (((i & 0xff00) >> 010) | \
                  ((i & 0x00ff) << 010))
#define sl(i) (self->swap ? btoll(i) : (i))
#define ss(i) (self->swap ? btols(i) : (i))


typedef struct {
  PyObject_HEAD
  /* Type-specific fields go here. */
  PyObject                *pFile;
  struct pcap_file_header  header;
  char                     mode; /* 'r' or 'w' */
  int                      swap; /* swap endianness? */
} pcap_PcapObject;


static void
pcap_PcapObject_dealloc(PyObject *p)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  Py_CLEAR(self->pFile);
  self->ob_type->tp_free(p);
}


static PyObject *
pcap_PcapObject_new(PyTypeObject *type,
                    PyObject *args,
                    PyObject *kwds)
{
  PyObject *p;

  p = type->tp_alloc(type, 0);
  if (! p) {
    return NULL;
  }

  {
    pcap_PcapObject *self = (pcap_PcapObject *)p;

    self->pFile = NULL;
  }

  return p;
}


static int
pcap_PcapObject_init(PyObject *p,
                     PyObject *args,
                     PyObject *kwds)
{
  pcap_PcapObject *self     = (pcap_PcapObject *)p;
  static char     *kwlist[] = {"src", "mode", "snaplen", "linktype", NULL};
  char            *mode     = NULL;
  _uint32_t        snaplen  = 65535;
  _uint32_t        linktype = 1;
  PyObject        *pTmp     = NULL;
  PyObject        *pFile;       /* Don't decref, it's borrowed! */

  attempt {
    int tmp;

    tmp = PyArg_ParseTupleAndKeywords(args, kwds, "O|sll", kwlist, &pFile, &mode, &snaplen, &linktype);
    if (! tmp) break;

    if (PyString_Check(pFile)) {
      char *fn;

      fn = PyString_AsString(pFile);
      if (! fn) break;

      if (NULL == mode) {
        mode = "rb";
      }

      pFile = PyFile_FromString(fn, mode);
      if (! pFile) break;

      self->pFile = pFile;
    } else {
      self->pFile = pFile;
      Py_INCREF(self->pFile);
    }

    if ((! mode) || ('r' == mode[0])) {
      /* Try to read in the header. */

      pTmp = PyObject_CallMethod(pFile, "read", "i", sizeof(self->header));
      if (0 == mode) {
        /* If we're in auto-detect mode... */
        if (pTmp) {
          /* And it worked, then we become read-only */
          self->mode = 'r';
        } else {
          /* And it didn't work, then we become write-only */
          PyErr_Clear();
          self->mode = 'w';
        }
      } else {
        self->mode = mode[0];
      }
    } else {
      self->mode = mode[0];
    }

    if ('r' == self->mode) {
      if (! pTmp) break;

      {
        int   tmp;
        char *buf;
        int   len;

        tmp = PyString_AsStringAndSize(pTmp, &buf, &len);
        if (-1 == tmp) {
          break;
        }

        if (len != sizeof(self->header)) {
          PyErr_Format(PyExc_IOError, "Reading header returned wrong number of bytes");
          break;
        }

        memcpy(&(self->header), buf, len);
      }

      if (0xa1b2c3d4 == self->header.magic) {
        self->swap = 0;
      } else if (0xd4c3b2a1 == self->header.magic) {
        self->swap = 1;
      } else {
        PyErr_Format(PyExc_IOError, "Not a pcap file");
        break;
      }
    } else if ('w' == self->mode) {
      /* Write out header */

      memset(&(self->header), 0, sizeof(self->header));
      self->header.magic         = 0xa1b2c3d4;
      self->header.version_major = 2;
      self->header.version_minor = 4;
      self->header.snaplen       = snaplen;
      self->header.linktype      = linktype;
      self->swap                 = 0;

      pTmp = PyObject_CallMethod(pFile, "write", "s#", &(self->header), sizeof(self->header));
      if (! pTmp) break;
    } else {
      PyErr_Format(PyExc_IOError, "mode must be 'r' or 'w'");
      break;
    }
  }

  recover {
    Py_CLEAR(self->pFile);
    Py_CLEAR(pTmp);

    return -1;
  }

  return 0;
}


static PyObject *
pcap_PcapObject_read(PyObject *p)
{
  pcap_PcapObject    *self = (pcap_PcapObject *)p;
  struct pcap_pkthdr *hdr;
  PyObject           *pTmp = NULL;
  PyObject           *pBuf = NULL;
  PyObject           *pRet = NULL;

  attempt {
    if ('r' != self->mode) {
      PyErr_Format(PyExc_IOError, "can not read from writable stream");
      break;
    }

    pTmp = PyObject_CallMethod(self->pFile, "read", "i", sizeof(*hdr));
    if (! pTmp) break;

    {
      char *buf;
      int   len;
      int   tmp;

      tmp = PyString_AsStringAndSize(pTmp, &buf, &len);
      if (-1 == tmp) {
        break;
      }

      /* 0 bytes means end of file */
      if (0 == len) {
        pRet = Py_None;
        Py_INCREF(pRet);
        succeed;
      }

      if (len != sizeof(*hdr)) {
        PyErr_Format(PyExc_IOError, "Read returned wrong number of bytes (%d)", len);
        break;
      }

      /* Since buf points to something Python owns, we can just make hdr
         point there and let buf fall off the stack. */

      hdr = (struct pcap_pkthdr *)buf;
    }

    pBuf = PyObject_CallMethod(self->pFile, "read", "i", sl(hdr->caplen));
    if (! pBuf) break;
    Py_INCREF(pBuf);

    pRet = Py_BuildValue("(lll)O",
                         sl(hdr->ts.tv_sec),
                         sl(hdr->ts.tv_usec),
                         sl(hdr->len),
                         pBuf);
    if (! pRet) break;
  }

  Py_CLEAR(pTmp);
  Py_CLEAR(pBuf);

  recover {
    Py_CLEAR(pRet);

    return NULL;
  }

  return pRet;
}


static PyObject *
pcap_PcapObject_write(PyObject *p, PyObject *args)
{
  pcap_PcapObject    *self = (pcap_PcapObject *)p;
  char               *buf;
  struct pcap_pkthdr  hdr;
  PyObject           *pTmp = NULL;

  attempt {
    int tmp;

    if ('w' != self->mode) {
      PyErr_Format(PyExc_IOError, "can not write to readable stream");
      break;
    }

    tmp = PyArg_ParseTuple(args, "((lll)s#)",
                           &(hdr.ts.tv_sec), &(hdr.ts.tv_usec),
                           &(hdr.len),
                           &buf, &(hdr.caplen));
    if (! tmp) break;

    pTmp = PyObject_CallMethod(self->pFile, "write", "s#", &hdr, sizeof(hdr));
    if (! pTmp) break;

    Py_DECREF(pTmp); pTmp = NULL;

    pTmp = PyObject_CallMethod(self->pFile, "write", "s#", buf, hdr.caplen);
    if (! pTmp) break;
  }

  Py_CLEAR(pTmp);

  recover {
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}


static PyObject *
pcap_PcapObject_get_version(PyObject *p, void *ignored)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  return Py_BuildValue("(HH)", ss(self->header.version_major), ss(self->header.version_minor));
}


static PyObject *
pcap_PcapObject_get_thiszone(PyObject *p, void *ignored)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  return Py_BuildValue("l", sl(self->header.thiszone));
}


static PyObject *
pcap_PcapObject_get_sigfigs(PyObject *p, void *ignored)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  return Py_BuildValue("l", sl(self->header.sigfigs));
}


static PyObject *
pcap_PcapObject_get_snaplen(PyObject *p, void *ignored)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  return Py_BuildValue("l", sl(self->header.snaplen));
}


static PyObject *
pcap_PcapObject_get_linktype(PyObject *p, void *ignored)
{
  pcap_PcapObject *self = (pcap_PcapObject *)p;

  return Py_BuildValue("l", sl(self->header.linktype));
}


/* Iterator stuff */
static PyObject *pcap_PcapObject_iter(PyObject *);


static struct PyMethodDef
pcap_PcapObject_methods[] = {
  {"read", (PyCFunction)pcap_PcapObject_read, METH_NOARGS, "Read a packet"},
  {"next", (PyCFunction)pcap_PcapObject_read, METH_NOARGS, "Read a packet"},
  {"write", (PyCFunction)pcap_PcapObject_write, METH_VARARGS, "Write a packet"},
  {NULL}  /* Sentinel */
};


static struct PyGetSetDef
pcap_PcapObject_getset[] = {
  {"version", pcap_PcapObject_get_version, NULL, "Version of file", NULL},
  {"thiszone", pcap_PcapObject_get_thiszone, NULL, "GMT to local correction", NULL},
  {"sigfigs", pcap_PcapObject_get_sigfigs, NULL, "Accuracy of timestamps", NULL},
  {"snaplen", pcap_PcapObject_get_snaplen, NULL, "Max length of saved portion of each packet", NULL},
  {"linktype", pcap_PcapObject_get_linktype, NULL, "Data link type", NULL},
  {NULL}  /* Sentinel */
};


static PyTypeObject pcap_PcapType = {
  PyObject_HEAD_INIT(NULL)
  0,                            /* ob_size */
  "pcap.pcap",                  /* tp_name */
  sizeof(pcap_PcapObject),      /* tp_basicsize */
  0,                            /* tp_itemsize */
  pcap_PcapObject_dealloc,      /* tp_dealloc */
  0,                            /* tp_print */
  0,                            /* tp_getattr */
  0,                            /* tp_setattr */
  0,                            /* tp_compare */
  0,                            /* tp_repr */
  0,                            /* tp_as_number */
  0,                            /* tp_as_sequence */
  0,                            /* tp_as_mapping */
  0,                            /* tp_hash */
  0,                            /* tp_call */
  0,                            /* tp_str */
  0,                            /* tp_getattro */
  0,                            /* tp_setattro */
  0,                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,           /* tp_flags */
  "Pcap file reader",           /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  pcap_PcapObject_iter,         /* tp_iter */
  0,                            /* tp_iternext */
  pcap_PcapObject_methods,      /* tp_methods */
  0,                            /* tp_members */
  pcap_PcapObject_getset,       /* tp_getset */
  0,                            /* tp_base */
  0,                            /* tp_dict */
  0,                            /* tp_descr_get */
  0,                            /* tp_descr_set */
  0,                            /* tp_dictoffset */
  pcap_PcapObject_init,         /* tp_init */
  0,                            /* tp_alloc */
  pcap_PcapObject_new,          /* tp_new */
  0,                            /* tp_free */
};


/******************** Pcap Iterator ********************/

typedef struct {
  PyObject_HEAD
  PyObject *pcap;
} pcap_PcapIterObject;


static void pcap_PcapIterObject_dealloc(PyObject *p);
static PyObject *pcap_PcapIterObject_next(PyObject *p);

PyTypeObject pcap_PcapIterType = {
  PyObject_HEAD_INIT(NULL)
  0,                            /* ob_size */
  "pcap.pcap_iterator",         /* tp_name */
  sizeof(pcap_PcapIterObject),  /* tp_basicsize */
  0,                            /* tp_itemsize */
  pcap_PcapIterObject_dealloc,  /* tp_dealloc */
  0,                            /* tp_print */
  0,                            /* tp_getattr */
  0,                            /* tp_setattr */
  0,                            /* tp_compare */
  0,                            /* tp_repr */
  0,                            /* tp_as_number */
  0,                            /* tp_as_sequence */
  0,                            /* tp_as_mapping */
  0,                            /* tp_hash */
  0,                            /* tp_call */
  0,                            /* tp_str */
  0,                            /* tp_getattro */
  0,                            /* tp_setattro */
  0,                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,           /* tp_flags */
  "Pcap file iterator",         /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  PyObject_SelfIter,            /* tp_iter */
  pcap_PcapIterObject_next,     /* tp_iternext */
  0,                            /* tp_methods */
  0,                            /* tp_members */
};


static PyObject *
pcap_PcapObject_iter(PyObject *p)
{
  pcap_PcapObject     *self = (pcap_PcapObject *)p;
  pcap_PcapIterObject *it   = NULL;
  PyObject            *pIt;

  attempt {
    if ('r' != self->mode) {
      PyErr_Format(PyExc_IOError, "can not read from writable stream");
      break;
    }

    it = PyObject_New(pcap_PcapIterObject, &pcap_PcapIterType);
    if (! it) break;

    pIt = PyObject_Init((PyObject *)it, &pcap_PcapIterType);
    if (pIt != (PyObject *)it) break;

    it->pcap = p;
    Py_INCREF(it->pcap);
  }

  recover {
    if (it) {
      Py_CLEAR(it->pcap);
      Py_CLEAR(it);
    }
    return NULL;
  }

  return (PyObject *)it;
}


static void
pcap_PcapIterObject_dealloc(PyObject *p)
{
  pcap_PcapIterObject *self = (pcap_PcapIterObject *)p;

  Py_CLEAR(self->pcap);
  PyObject_Del(p);
  //self->ob_type->tp_free(p);
}


static PyObject *
pcap_PcapIterObject_next(PyObject *p)
{
  pcap_PcapIterObject *self = (pcap_PcapIterObject *)p;
  PyObject            *pRet = NULL;

  pRet = pcap_PcapObject_read(self->pcap);
  if (pRet == Py_None) {
    Py_DECREF(pRet);
    Py_DECREF(self->pcap);
    self->pcap = NULL;
    return NULL;
  }

  return pRet;
}


static PyMethodDef pcap_methods[] = {
  {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initpcap(void)
{
  PyObject* m;

  pcap_PcapType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&pcap_PcapType) < 0)
    return;

  m = Py_InitModule3("pcap", pcap_methods,
                     "Reads pcap files in a less-sucky way");

  {
    PyObject *version;

    version = Py_BuildValue("ii", 2, 0);
    PyModule_AddObject(m, "version", version); /* Steals reference */
  }

  /* It's probably not strictly necessary to incref each time, since
     it's not possible to delete these. */

  Py_INCREF(&pcap_PcapType);
  PyModule_AddObject(m, "pcap", (PyObject *)&pcap_PcapType);

  Py_INCREF(&pcap_PcapType);
  PyModule_AddObject(m, "open", (PyObject *)&pcap_PcapType);

  Py_INCREF(&pcap_PcapType);
  PyModule_AddObject(m, "open_offline", (PyObject *)&pcap_PcapType);
}
