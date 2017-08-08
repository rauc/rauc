Design Checklist
================

This checklist is intended to help you verify that your design and implementation
cover the important corner-cases and details.
Even if not all items are ticked off for your system, it's useful to have at
least thought about them.
Most of these are general considerations and not strictly RAUC specific.

General
-------

* System compatible is specific enough ☐
* Bundle version policy defined ☐
* Bundle contains all software components ☐
* Bundles are created automatically by a build system ☐
* Bundle deployment mechanism defined (pull or push via the network, from
  USB/SD, …) ☐

Slot Layout
-----------

* Slot layout provides the desired redundancy ☐
* Complexity vs. simplicity trade-offs understood ☐
* Single points of failure identified and well tested ☐
* Factory disk image includes all slots with default contents ☐
* Appropriate image formats selected (tar or filesystem-image) ☐
* Bootloader uses the same names configured in ``system.conf`` as ``bootname`` ☐
* Bootloader update mechanism defined (or declared as fixed) ☐

Recovery Mechanism
------------------

* The initial (factory) boot configuration is correct ☐
* Boot failures are detected by the bootloader ☐
* Booting the same slot is retried the correct number of times (once or more) ☐
* The behavior if one slot fails to boot is defined (fallback to old version or
  not) ☐
* The behavior if all slots fail to boot is defined (retry or poweroff) ☐

If Using a HW Watchdog for Error Detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Watchdog is never disabled before application is ready ☐
* Bootloader distinguishes watchdog resets from normal boot ☐
* Bootloader ensures the watchdog is enabled before starting the kernel ☐
* The watchdog reset reinitializes the whole system (power supplies, storage,
  SoC, …) ☐
* All essential services are monitored by the watchdog ☐

If Not Using a HW Watchdog for Error Detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Bootloader detects failed boots via a counter ☐
* Boot counter is reset on a successful boot ☐
* All essential services work before confirming the current boot as successful ☐

Security
--------

* PKI configured ☐
* Certificate validity periods defined ☐

  * Systems always have correct time ☐ *or*
  * Validity period is large enough ☐
* Key revocation tested ☐
* Key rollover tested ☐
* Separate development and release keys deployed ☐
* Per-user or per-role keys deployed ☐

Data Migration
--------------

* Passwords/SSH keys are preserved during updates ☐
* Shared data is handled correctly during up- and downgrades ☐
