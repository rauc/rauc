if not get_option('service')
  subdir_done()
endif

rauc_service = configure_file(
  input : 'rauc.service.in',
  output : 'rauc.service',
  configuration : conf
)
install_data(rauc_service, install_dir : systemdunitdir)

rauc_dbus_service = configure_file(
  input : 'de.pengutronix.rauc.service.in',
  output : 'de.pengutronix.rauc.service',
  configuration : conf
)
install_data(rauc_dbus_service, install_dir : dbussystemservicedir)

rauc_dbus_wrapper = configure_file(
  input : 'rauc-service.sh.in',
  output : 'rauc-service.sh',
  configuration : conf
)
install_data(rauc_dbus_wrapper, install_dir : dbuswrapperdir, install_mode : 'rwxr-xr-x')

rauc_dbus_policy = configure_file(
  input : 'de.pengutronix.rauc.conf',
  output : 'de.pengutronix.rauc.conf',
  copy : true
)
install_data(rauc_dbus_policy, install_dir : dbuspolicydir)

if polkitdep.found()
  polkitactiondir = get_option('polkitactiondir')
  if polkitactiondir == ''
    polkitactiondir = polkitdep.get_variable(pkgconfig : 'policydir', default_value : datadir / 'polkit-1' / 'actions')
  endif
  install_data('de.pengutronix.rauc.policy', install_dir : polkitactiondir)
endif

install_data('rauc.catalog', install_dir : systemdcatalogdir)
