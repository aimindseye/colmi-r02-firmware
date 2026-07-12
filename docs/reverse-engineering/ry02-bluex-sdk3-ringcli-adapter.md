# RY02 BlueX SDK3 RingCLI Adapter r1

**Source gate:** accepted r2 pass  
**SDK base:** `examples/demo/ble_custom_profile`  
**Mode:** build-only  
**Device action:** none

## Evidence incorporated

The accepted source gate establishes:

```text
custom 128-bit service database through attm_svc_create_db_128
write handling through GATTC_WRITE_REQ_IND
write confirmation through GATTC_WRITE_CFM
notifications through GATTC_SEND_EVT_CMD with GATTC_NOTIFY
advertising through gapm_start_advertise_cmd
startup_apollo00_ble.s
generic user_link.txt at FLASH_MAPPED_ADDR 0x00800000
```

## Adapter design

One SDK profile task owns two services. Each service uses six attributes:

```text
service declaration
write characteristic declaration
write value
notify characteristic declaration
notify value
CCCD
```

The profile stores both dynamically assigned service start handles. Exact
characteristic handles are derived from each start handle and the verified
attribute index order.

## Safety boundary

The generic SDK linker remains unchanged. The adapter must not be packaged as
an R02 OTA image and must not be installed on the ring.

A successful materialization proves source integration only. A separate ARMCC
build is still required to prove SDK compilation.
