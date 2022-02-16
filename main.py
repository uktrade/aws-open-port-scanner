import boto3
import nmap3

nmap = nmap3.NmapHostDiscovery()

AWS_ACCOUNT_PROFILE_NAMES = []

PUBLIC_IP_WHITELIST = []

AWS_REGION = "eu-west-2"


def scan_address(address):
    return nmap.nmap_portscan_only(address, args="-F")


if __name__ == "__main__":

    profiles = AWS_ACCOUNT_PROFILE_NAMES or boto3.session.Session().available_profiles

    for profile in profiles:
        print("--------------------------")
        print(f"scanning aws account: {profile}")

        session = boto3.session.Session(profile_name=profile, region_name=AWS_REGION)

        ### EC2
        ec2 = session.resource("ec2")

        instances = ec2.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        for instance in instances:
            # TODO: Do we need to consider multiple ENIs?
            if instance.public_ip_address:
                if instance.public_ip_address in PUBLIC_IP_WHITELIST:
                    print(f"EC2 {instance.id} {instance.public_ip_address} is whitelisted; skipping")
                else:
                    print(f"EC2 {instance.id} {instance.public_ip_address} scanning")
                    results = scan_address(instance.public_ip_address)
                    # breakpoint()
                    print("-----------------------------------")
                    print(results)
                    

        ### ECS/Fargate
        ecs = session.client("ecs")
        clusters = ecs.list_clusters()

        for cluster in clusters["clusterArns"]:
            tasks = ecs.list_tasks(cluster=cluster, desiredStatus='RUNNING')

            if tasks["taskArns"]:

                tasks = ecs.describe_tasks(
                    cluster=cluster,
                    tasks=tasks["taskArns"],
                )

                for task in tasks["tasks"]:
                    for attachment in task["attachments"]:
                        if attachment["type"] == "ElasticNetworkInterface":
                            for k, v in attachment.items():
                                # NOTE: We don't currently have any ECS/Fargate tasks in public subnets with public ips
                                # so this isn't wired up
                                if k.lower().startswith("public"):
                                    print(f"ECS {cluster} {task['details']['id']} {v} scanning")
