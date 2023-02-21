# vr-security-hawk
Observability of AWS Infrastructure Security Across Accounts

![image](/architecture_diagram.png)

Deploying the Security Hawk Dashboard in Grafana or QuickSight is simple with the templates provided.

## Deploy Grafana Dashboard

1. Create a dashboard in Grafana using the import option.
2. Select and load the json file containing the dashboard template in the Grafana folder 

## Deploy QuickSight Dashboard

1. Navigate to the quicksight.py script located in the QuickSight folder
2. Enter the AWS Account ID where you want the dashboard deployed, as well as the ARN of the principal who will have access to the dashboard. 
3. Run the script to deploy the dashboard.


