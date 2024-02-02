package tfplanadapt

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/types"
)

func adaptEC2(g *Graph) ec2.EC2 {
	return ec2.EC2{
		Instances: adaptInstances(g),
	}
}

func adaptInstances(g *Graph) []ec2.Instance {
	var instances []ec2.Instance
	for _, res := range g.FindResourcesByType("aws_instance") {
		instance := ec2.Instance{
			UserData:        res.GetStringAttr("user_data"),
			MetadataOptions: getMetadataOptions(res),
		}

		if launchTemplate := findRelatedLaunchTemplate(res); launchTemplate != nil {
			instance = launchTemplate.Instance
		}

		instance.RootBlockDevice = &ec2.BlockDevice{
			Encrypted: res.GetAttr("root_block_device").GetBoolAttr("encrypted"),
		}

		for _, blockDevice := range res.GetAttr("ebs_block_device").ToList() {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, &ec2.BlockDevice{
				Encrypted: blockDevice.GetBoolAttr("encrypted"),
			})
		}

		for _, res := range g.FindResourcesByType("aws_ebs_encryption_by_default") {
			if res.GetBoolAttr("enabled").IsFalse() {
				continue
			}

			instance.RootBlockDevice.Encrypted = types.BoolDefault(true, types.Metadata{})
			for i := 0; i < len(instance.EBSBlockDevices); i++ {
				ebs := instance.EBSBlockDevices[i]
				ebs.Encrypted = types.BoolDefault(true, types.Metadata{})
			}
		}

		instances = append(instances, instance)
	}

	return instances
}

func findRelatedLaunchTemplate(n *Node) *ec2.LaunchTemplate {
	if launchTemplate := n.FindRelated("aws_launch_template", "launch_template.id", "id"); launchTemplate != nil {
		return adaptLaunchTemplate(launchTemplate)
	}

	if launchTemplate := n.FindRelated("aws_launch_template", "launch_template.name", "name"); launchTemplate != nil {
		return adaptLaunchTemplate(launchTemplate)
	}

	return nil
}

func adaptLaunchTemplate(n *Node) *ec2.LaunchTemplate {
	return &ec2.LaunchTemplate{
		Instance: ec2.Instance{
			MetadataOptions: getMetadataOptions(n),
			UserData:        n.GetStringAttr("user_data"),
		},
	}
}

func getMetadataOptions(n *Node) ec2.MetadataOptions {
	return ec2.MetadataOptions{
		HttpTokens:   n.GetAttr("metadata_options").GetStringAttr("http_tokens"),
		HttpEndpoint: n.GetAttr("metadata_options").GetStringAttr("http_endpoint"),
	}
}
