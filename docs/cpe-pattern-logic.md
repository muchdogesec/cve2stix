## Indicator `patterns`

This document describes how `patterns` in Indicator objects are created.

### Simple Relationships

[CVE-2022-29098 offers a good example of simple relationships](https://nvd.nist.gov/vuln/detail/CVE-2022-29098).

```json
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "30687628-5C7F-4BB5-B990-93703294FDF0"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "68291D44-DBE1-4923-A848-04E64288DC23"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DCC55FA4-AD91-4DA6-B60E-A4E34DDAE95A"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B948CD53-3D17-4230-9B77-FCE8E0E548B9"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "5AB99A1A-8DD3-4DDE-B70C-0E91D1D3B682"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "61F14753-D64C-4E8B-AA94-07E014848B4D"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

1. `cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*` `OR`,
2. `cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*` `OR`,
3. `cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*` `OR`,
4. `cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*` `OR`,
5. `cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*` `OR`,
6. `cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*`

As such, in this example the `pattern` in the Indicator would be as follow;

```json
"pattern": "( [ (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.0.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.1.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.0:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.2.1:*:*:*:*:*:*:*') OR (software.cpe='cpe:2.3:a:dell:powerscale_onefs:9.3.0:*:*:*:*:*:*:*') ] )"
```

The CPE statements are joined by `OR` as this is the top level `operator` in the API response (of course, in many cases this can be an `AND`).

### Running On/With Relationships

[Let me demonstrate how more complex Relationships are modelled using the example CVE-2022-27948](https://nvd.nist.gov/vuln/detail/CVE-2022-27948).

```json
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "86619D7A-ACB6-489C-9C29-37C6018E5B4B"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_s_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "FD68704D-C711-491F-B278-B02C6866738C"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:tesla:model_x_firmware:*:*:*:*:*:*:*:*",
                                        "versionEndIncluding": "2022-03-26",
                                        "matchCriteriaId": "C3517683-8493-4D0D-9792-5C9034B1F0B3"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "825A79FD-C872-4564-9782-83BEEADDF5D9"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_s:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "8D28E699-B843-4641-9BA6-406D88231E7C"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:tesla:model_x:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "C550FF8A-58ED-4265-B33F-10AFDEA95519"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

Here there is one `nodes` again, however this time there are also two `cpeMatch`es inside it.

Note how in the Simple Relationships pattern all CPE key values were wrapped in square brackets (`[]`). Each CPE inside a `cpeMatch` is wrapped in square brackets.

So in this example I get pattern that will look like;

```json
    "pattern": "[ (software.cpe = 'A') OR (software.cpe = 'B') OR (software.cpe = 'N') ] AND [ (software.cpe = '1') OR (software.cpe = '2') OR (software.cpe = '0') ]",
```

Note how the `AND` joins the two square brackets, that's because the top level `operator` in the CVE response shown above is an `AND`. The CPE statements are joined by `OR` as this is the top level `operator` in the API response (of course, in many cases this can be an `AND`).

### Advanced Relationships

[I will use CVE-2019-18939 to demonstrate another more complex `configuration`](https://nvd.nist.gov/vuln/detail/CVE-2019-18939).

```json
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "286DA904-5631-4AAF-86DE-97C23982D2C5"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "33113AD0-F378-49B2-BCFC-C57B52FD3A04"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "285F4E29-E299-4F83-9F7E-BB19933AD654"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "F5D8290F-3541-4452-99CB-0766CDC59073"
                                    },
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "9C2CF19C-7EDE-4E3C-A736-E6736FF03FDC"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "38BE17DA-7C5E-427E-B824-151EB27CFF26"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

In this CVE there are four nodes, so this time cve2stix will join the patterns with `OR` statement (because there is no top level operator -- see more advanced relationships for dealing with these).

This gives four patterns...

Pattern one;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ]",
```

Pattern two;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ]",
```

Pattern three;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ]",
```

Pattern four;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ]",
```

Which form a single pattern inside the Indicator SDO as follows (each above pattern is joined with `OR` in the final pattern as there is no top level `operator` in the NVD response);

```json
    "pattern": "( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2a:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu3:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu3_firmware:3.47.18:*:*:*:*:*:*:*') ] ) OR ( [ (software.cpe = 'cpe:2.3:a:hm-print_project:hm-print:1.2:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:h:eq-3:homematic_ccu2:-:*:*:*:*:*:*:*') AND (software.cpe = 'cpe:2.3:o:eq-3:homematic_ccu2_firmware:2.47.20:*:*:*:*:*:*:*') ] )",
```

### (More) Advanced Relationships

Advance relationships are made slightly more complicated. For this I'll use CVE-2020-3543.

```json
                "configurations": [
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "955AED3C-3ED2-4467-AAA5-510521CD56E7"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "EC586459-C532-4A89-8C43-58DA17181A38"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "0C59F1EE-2E1C-4001-A9A7-73B92F9827AB"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "B783A438-0D5A-4BA7-97E0-0FA917045B37"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "DD32F59C-A08D-4692-9F79-5F8F419B5B18"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "42E1CC6F-8A71-4012-ABF8-F0DF96B23949"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "934836A7-DBBD-44CF-8CE5-28C2FC7AC754"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "BD2510BB-580C-4826-BE9D-4879F2B8BDA5"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "4E28EB73-9705-4BED-9969-50DE456F8B5F"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "12067AE1-9A55-43BE-8C75-849E060AF41A"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D84B5451-961F-4118-B288-C94CDEC6D40A"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "AA06EF29-7996-4916-90E1-6A569EB95C6B"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "D1397782-897F-44FB-A42D-5BAEF0CDAB77"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "3214D558-A6FF-4B03-947B-40AD12355235"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "37D529B4-C32B-4DFE-A216-C7A18228DA15"
                                    }
                                ]
                            },
                            {
                                "operator": "OR",
                                "negate": false,
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "39E0E98A-F382-4AA8-B940-78A78C99736A"
                                    }
                                ]
                            }
                        ]
                    }
                ],
```

See hee how you have a top level `operator` for each node. In this case the `operator` is always `AND`.

Pattern one;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern two;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern three;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern four;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern five;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern six;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern seven;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*') ]",
```

Pattern eight;

```json
    "pattern": "[ (software.cpe = 'cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*') ]",
```

This will create a final pattern with all 8 patterns, joined with an `AND` statement, as this is the top level operator. Here is what it would look like

```json
    "pattern": "( [ (software.cpe = 'cpe:2.3:o:cisco:8000p_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8000p_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8020_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8020_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8030_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8030_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8070_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8070_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8400_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8400_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8620_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8620_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8630_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8630_ip_camera:-:*:*:*:*:*:*:*') ] ) AND ( [ (software.cpe = 'cpe:2.3:o:cisco:8930_speed_dome_ip_camera_firmware:1.0.9-4:*:*:*:*:*:*:*') OR (software.cpe = 'cpe:2.3:h:cisco:8930_speed_dome_ip_camera:-:*:*:*:*:*:*:*') ] )",
```

### A note on patterns

**Recursion errors**

Some STIX patterns generated for Indicator objects are very long (e.g. CVE-2021-3942). This results in recursion errors using the default Python limit (1000). Thus the recursion limit is increased and set to 10,000 in this code to handle larger patterns (in `cve2stix/parse_api_response.py`).

Note, this is hacky. However, even set at 5000, some CVEs with very long patterns (arguably too long), cause errors. You will see these in the logs as follows (shortened for brevity here);

```txt
2023-11-01 08:34:10,086 | ERROR | Indicator with issue -> CVE => CVE-2016-1409, Error: maximum recursion depth exceeded, Indicator Dict:
...
```

A list of known problematic CVEs for a backfill run on October 31st 2023;

* CVE-2016-1409
* CVE-2016-6380
* CVE-2017-6770

If the recursion limit is set too low, the Indicator objects for these will not appear in the resulting bundles (the Vulnerability objects will be present).

**JSON escapes**

Some CPEs in the NVD API response contain JSON escapes, e.g. in CVE-2006-4469

```txt
cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*
```

This causes errors with pattern generation. As such, when the string `\\` is identified in a pattern it is converted into `\\\\` to pass valid JSON parsing.