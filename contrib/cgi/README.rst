RAUC CGI
========

This provides a simple stand-alone CGI interface for RAUC. Slot status and
progress queries are possible as well as bundle upload and installation.

This should serve as an example for controlling RAUC via web. It is a much
simpler alternative to the hawkbit-client. It is also useful as a
demonstration on how to control RAUC via D-Bus in C/GLib.

Features
--------

* **GET /?status**: slot status information in JSON format implemented using
  `RAUC's D-Bus method GetSlotStatus <http://rauc.reayydthedocs.io/en/latest/reference.html#the-getslotstatus-method>`_
* **GET /?progress**: upload and installation progress using RAUC's D-Bus
  `signals <http://rauc.readthedocs.io/en/latest/reference.html#signal-details>`_
  and `properties <http://rauc.readthedocs.io/en/latest/reference.html#property-details>`_
* **PUT /**: uploading a bundle and triggering RAUC to install it via RAUC's
  `Install method <http://rauc.readthedocs.io/en/latest/reference.html#the-install-method>`_

Building from Sources
---------------------

::

    ./autogen.sh
    ./configure
    make

Example Usage
-------------

Usually a web server calls the rauc-cgi binary. In order to test and
demonstrate rauc-cgi (like any other CGI binary) it can also be called manually
like a web server would do. For better readability the JSON output is formatted
*here only*:

Status
~~~~~~

The slot status structure is directly based on the GVariant structure of
`GetSlotStatus <http://rauc.reayydthedocs.io/en/latest/reference.html#the-getslotstatus-method>`_.

::

    $ REQUEST_METHOD=GET QUERY_STRING=status rauc-cgi
    Status: 200 OK
    Content-type: application/json

    {
        "bootloader.0": {
            "bundle.build": "20180316164842",
            "bundle.compatible": "FooCorp Super BarBazzer",
            "bundle.description": "Introduction of Galactic Feature XYZ",
            "bundle.version": "2018.03-1",
            "class": "bootloader",
            "description": "",
            "device": "/dev/mmcblk1",
            "installed.count": 1,
            "installed.timestamp": "2018-04-09T20:41:13Z",
            "sha256": "bcccd4c390568bcd641b985045942623982f4b22f562ad7dc2f7257d4be2b21c",
            "size": 571330,
            "state": "inactive",
            "status": "ok",
            "type": "boot-emmc"
        },
        "rootfs.0": {
            "activated.count": 24,
            "activated.timestamp": "2018-04-09T20:41:14Z",
            "boot-status": "good",
            "bootname": "system0",
            "bundle.build": "20180316164842",
            "bundle.compatible": "FooCorp Super BarBazzer",
            "bundle.description": "Introduction of Galactic Feature XYZ",
            "bundle.version": "2018.03-1",
            "class": "rootfs",
            "description": "",
            "device": "/dev/mmcblk1p1",
            "installed.count": 1,
            "installed.timestamp": "2018-04-09T14:56:03Z",
            "sha256": "f6cb1ac2e453bf92218d34d5fb9572214accd84850398d4ad2926b5e63e23f59",
            "size": 80657208,
            "state": "active",
            "status": "ok",
            "type": "ext4"
        },
        "rootfs.1": {
            "boot-status": "bad",
            "bootname": "system1",
            "bundle.build": "20180416164842",
            "bundle.compatible": "FooCorp Super BarBazzer",
            "bundle.description": "Introduction of Galactic Feature XYZ",
            "bundle.version": "2018.03-1",
            "class": "rootfs",
            "description": "",
            "device": "/dev/mmcblk1p2",
            "installed.count": 1,
            "installed.timestamp": "2018-04-09T14:56:03Z",
            "sha256": "f6cb1ac2e453bf92218d34d5fb9572214accd84850398d4ad2926b5e63e23f59",
            "size": 80657208,
            "state": "inactive",
            "status": "ok",
            "type": "ext4"
        }
    }

Progress
~~~~~~~~

The progress changes during bundle upload, e.g.:

::

    $ REQUEST_METHOD=GET QUERY_STRING=progress rauc-cgi
    Status: 200 OK
    Content-type: application/json

    {
        "installation_operation": "",
        "installation_progress": 0,
        "last_installation_error": "",
        "last_installation_success": true,
        "upload_client_id": "engineer123",
        "upload_progress": 57,
        "will_reboot": false
    }

And during installation, e.g.:

::

    $ REQUEST_METHOD=GET QUERY_STRING=progress rauc-cgi
    Status: 200 OK
    Content-type: application/json

    {
        "installation_operation": "installing (Verifying signature)",
        "installation_progress": 20,
        "last_installation_error": "",
        "last_installation_success": true,
        "upload_client_id": "engineer123",
        "upload_progress": 100,
        "will_reboot": false
    }

    $ REQUEST_METHOD=GET QUERY_STRING=progress rauc-cgi
    Status: 200 OK
    Content-type: application/json

    {
        "installation_operation": "installing (Determining target install group done.)",
        "installation_progress": 80,
        "last_installation_error": "",
        "last_installation_success": true,
        "upload_client_id": "engineer123",
        "upload_progress": 100,
        "will_reboot": false
    }


    $ REQUEST_METHOD=GET QUERY_STRING=progress rauc-cgi
    Status: 200 OK
    Content-type: application/json

    {
        "installation_operation": "idle (Determining slot states done.)",
        "installation_progress": 100,
        "last_installation_error": "",
        "last_installation_success": true,
        "upload_client_id": "engineer123",
        "upload_progress": 100,
        "will_reboot": true
    }


Upload and Installation
~~~~~~~~~~~~~~~~~~~~~~~

It is possible to define custom headers (see src/cgi.c). As an example
UPLOAD_CLIENT_ID is defined already. This propagates into the progress JSON
(see above). Uploads can be simulated with:

::

    $ HTTP_UPLOAD_CLIENT_ID=engineer123 CONTENT_LENGTH=$(stat -c "%s" mybundle.raucb) REQUEST_METHOD=PUT rauc-cgi < mybundle.raucb
    Status: 200 OK
    Content-type: text/plain

    Upload and install trigger executed successfully.

Known limitations
-----------------

* no authentication (out of scope)
* all status information and error messages are accessible unfiltered
* no multi-user access
* no distinction between CGI-triggered and alternatively triggered bundle
  installations
* it is assumed that the postinstall hook reboots the system shortly after
  installation succeeded (see will_reboot property, lock file is assumed to
  be deleted by reboot)
