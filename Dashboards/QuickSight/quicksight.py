import boto3
import json
import pprint

client = boto3.client('quicksight')


response = client.create_dashboard(
   AwsAccountId='', 
   DashboardId='security_hawk_from_template_definition',
   Permissions= [ 
      { 
         "Actions": ["quicksight:DescribeDashboard", "quicksight:ListDashboardVersions", "quicksight:UpdateDashboardPermissions", "quicksight:QueryDashboard", "quicksight:UpdateDashboard", "quicksight:DeleteDashboard", "quicksight:UpdateDashboardPublishedVersion", "quicksight:DescribeDashboardPermissions"],
         "Principal": ""
      }
   ],
   Definition= { 
      "DataSetIdentifierDeclarations": [{
         "DataSetArn": "arn:aws:quicksight:us-east-1:794551265196:dataset/88c0f253-c649-42a2-bd05-c071566ed3a5",
         "Identifier": "sh_findings"
      }],
      "CalculatedFields": [
            {
                "DataSetIdentifier": "sh_findings",
                "Name": "passed_score",
                "Expression": "ifelse(({severity_label} = \"CRITICAL\" AND {compliance_status} = \"PASSED\"), 10, ({severity_label} = \"HIGH\" AND {compliance_status}= \"PASSED\"), 7, ({severity_label} = \"MEDIUM\" AND {compliance_status} = \"PASSED\"), 5, ({severity_label} = \"LOW\" AND {compliance_status} = \"PASSED\"), 3,({severity_label} = \"INFORMATIONAL\" AND {compliance_status} = \"PASSED\"), 1, 0) "
            },
            {
                "DataSetIdentifier": "sh_findings",
                "Name": "weight",
                "Expression": "ifelse({severity_label} = \"CRITICAL\", 10, {severity_label} = \"HIGH\", 7, {severity_label} = \"MEDIUM\", 5, {severity_label} = \"LOW\", 3,{severity_label} = \"INFORMATIONAL\", 1, 0) "
            }
        ],
      "FilterGroups": [
            {
                "FilterGroupId": "b92af8bd-d8aa-49c5-ad60-e5d9b71a9cae",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "c0afef6e-7907-4fab-866a-79d82596d65c",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "CRITICAL"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "18b7313f-d89b-4aa9-ae22-0c3ebe1f8935"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "f14cfe19-0689-49b4-966c-926bcffcc0bb",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "8c31cc62-0a19-4c17-9946-ed0c5de3c9e8",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "18b7313f-d89b-4aa9-ae22-0c3ebe1f8935"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "26f72ba4-055b-4086-bf1c-ea0536f8ca20",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "ecb143f9-4b54-4d88-a384-32ccfde104f7",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "HIGH"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "b7037a9d-bed1-428f-b4bc-52def3868dc2"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "0e07ed63-904e-421e-8e36-fd2f851b12b1",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "7c5f6e28-7eb8-457d-a243-e6ceeac35569",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "b7037a9d-bed1-428f-b4bc-52def3868dc2"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "b5b16095-b05e-494a-8a5a-7bb3766527ab",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "84df758d-90f3-4a11-8db9-2d70192ecf9d",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "MEDIUM"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "e9b5df0d-b0ec-4a90-ac90-86bef245d114"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "7ce381d8-75f3-4587-84c2-0e5c45137f1f",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "14ad1ebf-cc1e-4730-b2a2-6d7582148787",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "e9b5df0d-b0ec-4a90-ac90-86bef245d114"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "9a68389e-66c7-403f-ba79-58b09858076d",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "09ba9a9e-90db-4ea9-8d5c-45e5c4b0d435",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "LOW"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "ac515a46-8af7-4c1a-86d5-251c90221057"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "95d38010-9dde-49f9-88c0-d3ba7509e178",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "844eca73-332d-4a8b-9c52-b55930c49df9",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "ac515a46-8af7-4c1a-86d5-251c90221057"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "236c7f16-42a4-461d-83b1-41552b1b1ef7",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "da668cf1-0b03-4e79-aa8b-ccc75126b4ca",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "LOW"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "54873acd-0826-4409-a5f4-3653cb52e1a4"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "bf657b62-b0db-4ea3-869c-24a9672dc89d",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "4af19316-8925-4d05-a04f-3c95214d7ef7",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "54873acd-0826-4409-a5f4-3653cb52e1a4"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "d52e87b8-4f64-48a5-b690-77baa206a1a5",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "eb1ffd71-8b85-4f46-9a4c-e2252bdc5d07",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "ab83413f-eaef-4f73-b759-58f15f477b2e"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "fba5cf79-326c-4b5d-99e0-f2584b7a4745",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "7a82c3de-5c09-4a91-95f1-f1f73da55925",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "ab83413f-eaef-4f73-b759-58f15f477b2e"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "990c408f-37c5-43ee-8109-9043960cf0df",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "8ecd87d1-7bb6-4f2c-bf54-82330e3fd0ed",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "4e6ab152-e2d5-4316-bc31-a60059620ce7"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "70c4be6f-e81b-486a-b327-3dc61fd3695a",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "dac83ce1-aae1-4384-a7d9-4ddedfe00d27",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "4e6ab152-e2d5-4316-bc31-a60059620ce7"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "52f73ea4-6b77-4c63-a71b-7508b53ef19a",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "51386c3e-4566-4bde-a3cf-cb4c062778a0",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "8b01e7f7-3067-4608-9cb9-5336559cec29"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "5264f08b-cca8-4f41-9601-7bad41c2f0ab",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "71d9e2d8-7384-4886-ba67-904c453f3cb3",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "8b01e7f7-3067-4608-9cb9-5336559cec29"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "aa5bd795-1da4-44e8-840f-ba1a5c54c0db",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "f9cae411-4319-491c-b074-55c9c65cb139",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "3e55105a-fa84-433f-bdba-f0b9d98bdb1f"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "ba3c33b4-e89a-483b-8005-b35fbe5b98dd",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "d51c5a5a-c8a8-48e8-867a-04df35c45a0f",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "3e55105a-fa84-433f-bdba-f0b9d98bdb1f"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "536ac639-6836-4d62-ac96-48431eaaef2a",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "4ad2d69d-1c76-4cf5-b6f7-d23b8b44a3f4",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "c2206a9f-204f-4fb5-a26d-ef6b5a9b526b"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "83a3c773-7464-47a7-b48a-0295c239d16f",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "393f870d-a8ea-42b1-9d23-6c3dd6548e91",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "c2206a9f-204f-4fb5-a26d-ef6b5a9b526b"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "79f3e189-0f4a-491b-b8fa-1b1b36507070",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "c2864987-bc1e-4e9b-9162-aac6c2157c4c",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "SelectAllOptions": "FILTER_ALL_VALUES"
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "40a1890c-f1c2-428c-b8dd-f0103fd0cc4a"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "143427a4-3e4a-4391-9360-640582b3868c",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "e2c61f81-f64b-44ab-a29b-e5c55c2ca245",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "40a1890c-f1c2-428c-b8dd-f0103fd0cc4a"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "8850814d-db65-4e1d-b2fe-696f1e312bd2",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "b3006de6-1b69-4632-9cfa-6d528549d93d",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "CRITICAL"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "dc4905d1-1c49-4595-af54-be68ef4d76d8"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "fbf9800a-7acd-4894-84a0-ae313ed9ad86",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "d61f3a17-7451-4a14-b0d9-be6788a8c0e1",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "dc4905d1-1c49-4595-af54-be68ef4d76d8"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "68e6aa24-c610-4e03-be3f-d919683bb878",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "5515a356-2733-4eb6-ae26-2f004d14b0d8",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "severity_label"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "CONTAINS",
                                    "CategoryValues": [
                                        "HIGH"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "59b569cb-8b52-4bc0-bb16-ac3f8e4e9477"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "54879f17-804b-4222-8ac1-9c2b69f4b3fd",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "2a70c2b9-0647-48c6-885a-3a7ac6b41bc5",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "59b569cb-8b52-4bc0-bb16-ac3f8e4e9477"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            },
            {
                "FilterGroupId": "f295b070-fb89-4503-9508-bf0cea7d2842",
                "Filters": [
                    {
                        "CategoryFilter": {
                            "FilterId": "07b6c364-d91f-435a-8ed5-db4b978e6e3d",
                            "Column": {
                                "DataSetIdentifier": "sh_findings",
                                "ColumnName": "compliance_status"
                            },
                            "Configuration": {
                                "FilterListConfiguration": {
                                    "MatchOperator": "DOES_NOT_CONTAIN",
                                    "CategoryValues": [
                                        "PASSED"
                                    ]
                                }
                            }
                        }
                    }
                ],
                "ScopeConfiguration": {
                    "SelectedSheets": {
                        "SheetVisualScopingConfigurations": [
                            {
                                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                                "Scope": "SELECTED_VISUALS",
                                "VisualIds": [
                                    "da9c881a-2b2f-4d69-a424-ffe2538b3683"
                                ]
                            }
                        ]
                    }
                },
                "Status": "ENABLED",
                "CrossDataset": "SINGLE_DATASET"
            }
        ],
      "Sheets": [
            {
                "SheetId": "36478f0a-42e2-40f4-accc-386adaa73543",
                "Name": "Sheet 1",
                "Visuals": [
                    {
                        "TableVisual": {
                            "VisualId": "da9c881a-2b2f-4d69-a424-ffe2538b3683",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Open Findings by Resource</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "TableAggregatedFieldWells": {
                                        "GroupBy": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.resource_type.1.1675792499085",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "resource_type"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "COUNT"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "RowSort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ]
                                },
                                "TableOptions": {
                                    "HeaderStyle": {
                                        "TextWrap": "WRAP",
                                        "Height": 25
                                    }
                                },
                                "FieldOptions": {
                                    "SelectedFieldOptions": [
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.resource_type.1.1675792499085",
                                            "Width": "134px",
                                            "CustomLabel": "Resource"
                                        },
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                            "Width": "88px",
                                            "CustomLabel": "Findings"
                                        }
                                    ],
                                    "Order": []
                                }
                            },
                            "Actions": []
                        }
                    },
                    {
                        "GaugeChartVisual": {
                            "VisualId": "580e112b-d0f7-4b46-b267-de49029f97f5",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Security Score</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "NumericalMeasureField": {
                                                "FieldId": "0582fc92-a7c7-4e0e-8ad0-f078f0d79728.1.1675722155498",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "passed_score"
                                                },
                                                "AggregationFunction": {
                                                    "SimpleNumericalAggregation": "SUM"
                                                }
                                            }
                                        }
                                    ],
                                    "TargetValues": [
                                        {
                                            "NumericalMeasureField": {
                                                "FieldId": "f36a4e67-e491-412e-98ff-1c2f6eb6aa2b.1.1675721085026",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "weight"
                                                },
                                                "AggregationFunction": {
                                                    "SimpleNumericalAggregation": "SUM"
                                                }
                                            }
                                        }
                                    ]
                                },
                                "GaugeChartOptions": {
                                    "PrimaryValueDisplayType": "COMPARISON",
                                    "Comparison": {
                                        "ComparisonMethod": "PERCENT"
                                    },
                                    "Arc": {
                                        "ArcAngle": 270.0,
                                        "ArcThickness": "LARGE"
                                    }
                                },
                                "DataLabels": {
                                    "Visibility": "HIDDEN",
                                    "MeasureLabelVisibility": "VISIBLE",
                                    "Overlap": "DISABLE_OVERLAP"
                                }
                            },
                            "ConditionalFormatting": {
                                "ConditionalFormattingOptions": [
                                    {
                                        "Arc": {
                                            "ForegroundColor": {
                                                "Solid": {
                                                    "Expression": "SUM({passed_score})/nullIf(SUM({weight}),0) <= 50.0",
                                                    "Color": "#DE3B00"
                                                }
                                            }
                                        }
                                    },
                                    {
                                        "Arc": {
                                            "ForegroundColor": {
                                                "Solid": {
                                                    "Expression": "(SUM({passed_score})/nullIf(SUM({weight}),0) >= 50.0) AND (SUM({passed_score})/nullIf(SUM({weight}),0) <= 60.0)",
                                                    "Color": "#FC850D"
                                                }
                                            }
                                        }
                                    },
                                    {
                                        "Arc": {
                                            "ForegroundColor": {
                                                "Solid": {
                                                    "Expression": "(SUM({passed_score})/nullIf(SUM({weight}),0) >= 60.0) AND (SUM({passed_score})/nullIf(SUM({weight}),0) <= 80.0)",
                                                    "Color": "#F7E65A"
                                                }
                                            }
                                        }
                                    },
                                    {
                                        "Arc": {
                                            "ForegroundColor": {
                                                "Solid": {
                                                    "Expression": "(SUM({passed_score})/nullIf(SUM({weight}),0) >= 80.0) AND (SUM({passed_score})/nullIf(SUM({weight}),0) <= 100.0)",
                                                    "Color": "#2CAD00"
                                                }
                                            }
                                        }
                                    }
                                ]
                            },
                            "Actions": []
                        }
                    },
                    {
                        "TableVisual": {
                            "VisualId": "59b569cb-8b52-4bc0-bb16-ac3f8e4e9477",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Open High Severity Findings by Title</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "TableAggregatedFieldWells": {
                                        "GroupBy": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "title"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "RowSort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ]
                                },
                                "TableOptions": {
                                    "HeaderStyle": {
                                        "TextWrap": "WRAP",
                                        "Height": 25
                                    },
                                    "CellStyle": {
                                        "Height": 24
                                    }
                                },
                                "FieldOptions": {
                                    "SelectedFieldOptions": [
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                            "Width": "539px",
                                            "CustomLabel": "Title"
                                        },
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                            "Width": "88px",
                                            "CustomLabel": "Findings"
                                        }
                                    ],
                                    "Order": []
                                }
                            },
                            "Actions": []
                        }
                    },
                    {
                        "TableVisual": {
                            "VisualId": "dc4905d1-1c49-4595-af54-be68ef4d76d8",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Open Critical Severity Findings by Title</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "TableAggregatedFieldWells": {
                                        "GroupBy": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "title"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "RowSort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ]
                                },
                                "TableOptions": {
                                    "HeaderStyle": {
                                        "TextWrap": "WRAP",
                                        "Height": 25
                                    },
                                    "CellStyle": {
                                        "Height": 23
                                    }
                                },
                                "FieldOptions": {
                                    "SelectedFieldOptions": [
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                            "Width": "538px",
                                            "CustomLabel": "Title"
                                        },
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                            "Width": "88px",
                                            "CustomLabel": "Findings"
                                        }
                                    ],
                                    "Order": []
                                }
                            },
                            "Actions": []
                        }
                    },
                    {
                        "TableVisual": {
                            "VisualId": "40a1890c-f1c2-428c-b8dd-f0103fd0cc4a",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Findings by Title</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "TableAggregatedFieldWells": {
                                        "GroupBy": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "title"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "RowSort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ]
                                },
                                "TableOptions": {
                                    "HeaderStyle": {
                                        "TextWrap": "WRAP",
                                        "Height": 25
                                    }
                                },
                                "FieldOptions": {
                                    "SelectedFieldOptions": [
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.title.1.1675187002462",
                                            "Width": "492px",
                                            "CustomLabel": "Title"
                                        },
                                        {
                                            "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.1.1675187110836",
                                            "Width": "93px",
                                            "CustomLabel": "Findings"
                                        }
                                    ],
                                    "Order": []
                                }
                            },
                            "Actions": []
                        }
                    },
                    {
                        "BarChartVisual": {
                            "VisualId": "c2206a9f-204f-4fb5-a26d-ef6b5a9b526b",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Open Findings by Region</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "BarChartAggregatedFieldWells": {
                                        "Category": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.region.1.1675186878067",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "region"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.2.1675187270573",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ],
                                        "Colors": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186621474",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "severity_label"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "CategorySort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.region.1.1675186878067",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ],
                                    "CategoryItemsLimit": {
                                        "OtherCategories": "INCLUDE"
                                    },
                                    "ColorItemsLimit": {
                                        "OtherCategories": "INCLUDE"
                                    },
                                    "SmallMultiplesLimitConfiguration": {
                                        "OtherCategories": "INCLUDE"
                                    }
                                },
                                "Orientation": "VERTICAL",
                                "BarsArrangement": "CLUSTERED",
                                "VisualPalette": {
                                },
                                "ValueAxis": {
                                    "GridLineVisibility": "VISIBLE",
                                    "DataOptions": {
                                        "NumericAxisOptions": {
                                            "Scale": {
                                                "Logarithmic": {}
                                            }
                                        }
                                    }
                                },
                                "ColorLabelOptions": {
                                    "SortIconVisibility": "VISIBLE"
                                },
                                "Legend": {
                                    "Position": "RIGHT"
                                },
                                "DataLabels": {
                                    "Visibility": "HIDDEN",
                                    "MeasureLabelVisibility": "VISIBLE",
                                    "Overlap": "DISABLE_OVERLAP"
                                },
                                "Tooltip": {
                                    "TooltipVisibility": "VISIBLE",
                                    "SelectedTooltipType": "DETAILED",
                                    "FieldBasedTooltip": {
                                        "AggregationVisibility": "HIDDEN",
                                        "TooltipTitleType": "PRIMARY_VALUE",
                                        "TooltipFields": [
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186621474",
                                                    "Visibility": "VISIBLE"
                                                }
                                            },
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.region.1.1675186878067",
                                                    "Visibility": "VISIBLE"
                                                }
                                            },
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.2.1675187270573",
                                                    "Visibility": "VISIBLE"
                                                }
                                            }
                                        ]
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "BarChartVisual": {
                            "VisualId": "3e55105a-fa84-433f-bdba-f0b9d98bdb1f",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Open Findings by Account Id</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "BarChartAggregatedFieldWells": {
                                        "Category": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.awsaccountid.1.1675186609890",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "awsaccountid"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.2.1675187225766",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ],
                                        "Colors": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186621474",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "severity_label"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "CategorySort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.awsaccountid.1.1675186609890",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ],
                                    "CategoryItemsLimit": {
                                        "OtherCategories": "INCLUDE"
                                    },
                                    "ColorItemsLimit": {
                                        "OtherCategories": "INCLUDE"
                                    },
                                    "SmallMultiplesLimitConfiguration": {
                                        "OtherCategories": "INCLUDE"
                                    }
                                },
                                "Orientation": "VERTICAL",
                                "BarsArrangement": "CLUSTERED",
                                "VisualPalette": {
                                },
                                "ValueAxis": {
                                    "GridLineVisibility": "VISIBLE",
                                    "DataOptions": {
                                        "NumericAxisOptions": {
                                            "Scale": {
                                                "Logarithmic": {}
                                            }
                                        }
                                    }
                                },
                                "ColorLabelOptions": {
                                    "SortIconVisibility": "VISIBLE"
                                },
                                "Legend": {
                                    "Position": "RIGHT"
                                },
                                "DataLabels": {
                                    "Visibility": "HIDDEN",
                                    "MeasureLabelVisibility": "VISIBLE",
                                    "Overlap": "DISABLE_OVERLAP"
                                },
                                "Tooltip": {
                                    "TooltipVisibility": "VISIBLE",
                                    "SelectedTooltipType": "DETAILED",
                                    "FieldBasedTooltip": {
                                        "AggregationVisibility": "HIDDEN",
                                        "TooltipTitleType": "PRIMARY_VALUE",
                                        "TooltipFields": [
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.awsaccountid.1.1675186609890",
                                                    "Visibility": "VISIBLE"
                                                }
                                            },
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186621474",
                                                    "Visibility": "VISIBLE"
                                                }
                                            },
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.2.1675187225766",
                                                    "Visibility": "VISIBLE"
                                                }
                                            }
                                        ]
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "8b01e7f7-3067-4608-9cb9-5336559cec29",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>TOTAL PASSED</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "MEDIUM"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "4e6ab152-e2d5-4316-bc31-a60059620ce7",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>TOTAL FAILED</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "MEDIUM"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "PieChartVisual": {
                            "VisualId": "ab83413f-eaef-4f73-b759-58f15f477b2e",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>Failed Findings Percentage�</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "PieChartAggregatedFieldWells": {
                                        "Category": [
                                            {
                                                "CategoricalDimensionField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186028289",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "severity_label"
                                                    }
                                                }
                                            }
                                        ],
                                        "Values": [
                                            {
                                                "CategoricalMeasureField": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                    "Column": {
                                                        "DataSetIdentifier": "sh_findings",
                                                        "ColumnName": "id"
                                                    },
                                                    "AggregationFunction": "DISTINCT_COUNT"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "SortConfiguration": {
                                    "CategorySort": [
                                        {
                                            "FieldSort": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Direction": "DESC"
                                            }
                                        }
                                    ],
                                    "CategoryItemsLimit": {
                                        "OtherCategories": "INCLUDE"
                                    },
                                    "SmallMultiplesLimitConfiguration": {
                                        "OtherCategories": "INCLUDE"
                                    }
                                },
                                "DonutOptions": {
                                    "ArcOptions": {
                                        "ArcThickness": "WHOLE"
                                    }
                                },
                                "Legend": {
                                    "Position": "RIGHT",
                                    "Width": "143px"
                                },
                                "DataLabels": {
                                    "Visibility": "VISIBLE",
                                    "MeasureLabelVisibility": "VISIBLE",
                                    "Position": "OUTSIDE",
                                    "Overlap": "DISABLE_OVERLAP"
                                },
                                "Tooltip": {
                                    "TooltipVisibility": "VISIBLE",
                                    "SelectedTooltipType": "DETAILED",
                                    "FieldBasedTooltip": {
                                        "AggregationVisibility": "HIDDEN",
                                        "TooltipTitleType": "PRIMARY_VALUE",
                                        "TooltipFields": [
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.severity_label.1.1675186028289",
                                                    "Visibility": "VISIBLE"
                                                }
                                            },
                                            {
                                                "FieldTooltipItem": {
                                                    "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                    "Visibility": "VISIBLE"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "VisualPalette": {
                                    
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "54873acd-0826-4409-a5f4-3653cb52e1a4",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>\n  <inline font-size=\"10px\">INFORMATIONAL</inline>\n</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "MEDIUM"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "ac515a46-8af7-4c1a-86d5-251c90221057",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>LOW</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "MEDIUM"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "e9b5df0d-b0ec-4a90-ac90-86bef245d114",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>MEDIUM</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "SMALL"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "b7037a9d-bed1-428f-b4bc-52def3868dc2",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>\n  HIGH\n  <br/>\n</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {},
                                "KPIOptions": {
                                    "PrimaryValueFontConfiguration": {
                                        "FontSize": {
                                            "Relative": "MEDIUM"
                                        }
                                    }
                                }
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    },
                    {
                        "KPIVisual": {
                            "VisualId": "18b7313f-d89b-4aa9-ae22-0c3ebe1f8935",
                            "Title": {
                                "Visibility": "VISIBLE",
                                "FormatText": {
                                    "RichText": "<visual-title>CRITICAL</visual-title>"
                                }
                            },
                            "Subtitle": {
                                "Visibility": "VISIBLE"
                            },
                            "ChartConfiguration": {
                                "FieldWells": {
                                    "Values": [
                                        {
                                            "CategoricalMeasureField": {
                                                "FieldId": "4c208ce5-d084-46da-94f3-5229364174b4.id.0.1675118464432",
                                                "Column": {
                                                    "DataSetIdentifier": "sh_findings",
                                                    "ColumnName": "id"
                                                },
                                                "AggregationFunction": "DISTINCT_COUNT"
                                            }
                                        }
                                    ],
                                    "TargetValues": [],
                                    "TrendGroups": []
                                },
                                "SortConfiguration": {}
                            },
                            "Actions": [],
                            "ColumnHierarchies": []
                        }
                    }
                ],
                "TextBoxes": [
                    {
                        "SheetTextBoxId": "97bc19c6-5a35-41ed-a7c4-1074d9450ad4",
                        "Content": "<text-box>\n  <block align=\"center\">\n    <inline font-size=\"20px\">FAILED Findings by Severity</inline>\n  </block>\n</text-box>"
                    }
                ],
                "Layouts": [
                    {
                        "Configuration": {
                            "GridLayout": {
                                "Elements": [
                                    {
                                        "ElementId": "580e112b-d0f7-4b46-b267-de49029f97f5",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 0,
                                        "ColumnSpan": 7,
                                        "RowIndex": 0,
                                        "RowSpan": 7
                                    },
                                    {
                                        "ElementId": "97bc19c6-5a35-41ed-a7c4-1074d9450ad4",
                                        "ElementType": "TEXT_BOX",
                                        "ColumnIndex": 7,
                                        "ColumnSpan": 19,
                                        "RowIndex": 0,
                                        "RowSpan": 1
                                    },
                                    {
                                        "ElementId": "4e6ab152-e2d5-4316-bc31-a60059620ce7",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 26,
                                        "ColumnSpan": 3,
                                        "RowIndex": 0,
                                        "RowSpan": 4
                                    },
                                    {
                                        "ElementId": "da9c881a-2b2f-4d69-a424-ffe2538b3683",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 29,
                                        "ColumnSpan": 6,
                                        "RowIndex": 0,
                                        "RowSpan": 19
                                    },
                                    {
                                        "ElementId": "18b7313f-d89b-4aa9-ae22-0c3ebe1f8935",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 7,
                                        "ColumnSpan": 3,
                                        "RowIndex": 1,
                                        "RowSpan": 6
                                    },
                                    {
                                        "ElementId": "b7037a9d-bed1-428f-b4bc-52def3868dc2",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 10,
                                        "ColumnSpan": 2,
                                        "RowIndex": 1,
                                        "RowSpan": 3
                                    },
                                    {
                                        "ElementId": "ac515a46-8af7-4c1a-86d5-251c90221057",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 12,
                                        "ColumnSpan": 2,
                                        "RowIndex": 1,
                                        "RowSpan": 3
                                    },
                                    {
                                        "ElementId": "ab83413f-eaef-4f73-b759-58f15f477b2e",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 14,
                                        "ColumnSpan": 12,
                                        "RowIndex": 1,
                                        "RowSpan": 6
                                    },
                                    {
                                        "ElementId": "e9b5df0d-b0ec-4a90-ac90-86bef245d114",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 10,
                                        "ColumnSpan": 2,
                                        "RowIndex": 4,
                                        "RowSpan": 3
                                    },
                                    {
                                        "ElementId": "54873acd-0826-4409-a5f4-3653cb52e1a4",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 12,
                                        "ColumnSpan": 2,
                                        "RowIndex": 4,
                                        "RowSpan": 3
                                    },
                                    {
                                        "ElementId": "8b01e7f7-3067-4608-9cb9-5336559cec29",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 26,
                                        "ColumnSpan": 3,
                                        "RowIndex": 4,
                                        "RowSpan": 3
                                    },
                                    {
                                        "ElementId": "3e55105a-fa84-433f-bdba-f0b9d98bdb1f",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 0,
                                        "ColumnSpan": 14,
                                        "RowIndex": 7,
                                        "RowSpan": 6
                                    },
                                    {
                                        "ElementId": "c2206a9f-204f-4fb5-a26d-ef6b5a9b526b",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 14,
                                        "ColumnSpan": 15,
                                        "RowIndex": 7,
                                        "RowSpan": 6
                                    },
                                    {
                                        "ElementId": "40a1890c-f1c2-428c-b8dd-f0103fd0cc4a",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 0,
                                        "ColumnSpan": 14,
                                        "RowIndex": 13,
                                        "RowSpan": 8
                                    },
                                    {
                                        "ElementId": "dc4905d1-1c49-4595-af54-be68ef4d76d8",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 14,
                                        "ColumnSpan": 15,
                                        "RowIndex": 13,
                                        "RowSpan": 4
                                    },
                                    {
                                        "ElementId": "59b569cb-8b52-4bc0-bb16-ac3f8e4e9477",
                                        "ElementType": "VISUAL",
                                        "ColumnIndex": 14,
                                        "ColumnSpan": 15,
                                        "RowIndex": 17,
                                        "RowSpan": 4
                                    }
                                ],
                                "CanvasSizeOptions": {
                                    "ScreenCanvasSizeOptions": {
                                        "ResizeOption": "FIXED",
                                        "OptimizedViewPortWidth": "1600px"
                                    }
                                }
                            }
                        }
                    }
                ],
                "ContentType": "INTERACTIVE"
            }
        ]
   },
   Name= "security-hawk"

)

