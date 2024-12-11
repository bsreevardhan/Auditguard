from rest_framework import serializers
from .models import GroupList, GroupPolicy

class GroupListSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupList
        fields = ['id', 'group_name', 'level', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

    def validate_group_name(self, value):
        """
        Validate group name length and characters
        """
        if len(value) < 3:
            raise serializers.ValidationError("Group name must be at least 3 characters long")
        return value.strip()

class GroupPolicySerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='group_id.group_name', read_only=True)
    level = serializers.CharField(source='group_id.level', read_only=True)

    class Meta:
        model = GroupPolicy
        fields = ['id', 'group', 'policy_id', 'group_name', 'level']

    def validate(self, data):
        """
        Check that the policy_id is valid and not already in the group
        """
        group_id = data.get('group_id')
        policy_id = data.get('policy_id')

        # Check if this policy is already in the group
        if GroupPolicy.objects.filter(group_id=group_id, policy_id=policy_id).exists():
            raise serializers.ValidationError("This policy is already in the group")

        return data

# Nested serializer for detailed group view with policies
class GroupListDetailSerializer(serializers.ModelSerializer):
    policies = serializers.SerializerMethodField()
    policy_count = serializers.SerializerMethodField()

    class Meta:
        model = GroupList
        fields = ['id', 'group_name', 'level', 'created_at', 'updated_at', 'policies', 'policy_count']
        read_only_fields = ['created_at', 'updated_at']

    def get_policies(self, obj):
        group_policies = GroupPolicy.objects.filter(group=obj)
        return GroupPolicySerializer(group_policies, many=True).data

    def get_policy_count(self, obj):
        return GroupPolicy.objects.filter(group=obj).count()
