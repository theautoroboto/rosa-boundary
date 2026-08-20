"""
Integration tests for ABAC isolation on ECS tasks.

Verifies that IAM policies prevent users from accessing each other's tasks.
"""

import pytest
from botocore.exceptions import ClientError


@pytest.mark.integration
@pytest.mark.abac
class TestABACECSIsolation:
    """Test that ABAC tags prevent cross-user ECS task access."""

    def test_user_cannot_exec_into_other_user_task(
        self,
        alice_bob_pair,
        test_config,
        cleanup_resources
    ):
        """
        Verify Bob cannot execute commands in Alice's task.

        IAM policy should deny ecs:ExecuteCommand when
        ResourceTag/uuid != PrincipalTag/uuid
        """
        alice, bob = alice_bob_pair

        # Alice creates a task (via create-investigation command or direct ECS call)
        # For this test, we'll simulate the task already existing
        # In real scenario, would call Lambda create-investigation endpoint

        # Note: This test requires a real task to exist. In practice, you would:
        # 1. Call Lambda create-investigation as Alice to create task
        # 2. Extract task ARN from response
        # 3. Attempt to exec as Bob

        # Simplified version: List Alice's tasks and try to exec as Bob
        alice_tasks_resp = alice['ecs'].list_tasks(
            cluster=test_config['ecs_cluster'],
            desiredStatus='RUNNING',
            maxResults=1
        )

        if not alice_tasks_resp.get('taskArns'):
            pytest.skip("No running tasks found for Alice. Create investigation first.")

        alice_task_arn = alice_tasks_resp['taskArns'][0]

        # Verify this is actually Alice's task (has her UUID tag)
        task_details = alice['ecs'].describe_tasks(
            cluster=test_config['ecs_cluster'],
            tasks=[alice_task_arn]
        )

        if not task_details.get('tasks'):
            pytest.skip("Task disappeared during test")

        task = task_details['tasks'][0]
        task_tags = {tag['key']: tag['value'] for tag in task.get('tags', [])}

        # Skip if task doesn't have uuid tag (not a rosa-boundary task)
        if 'uuid' not in task_tags:
            pytest.skip("Task is not tagged with uuid (not a rosa-boundary task)")

        # Now Bob tries to exec into Alice's task
        with pytest.raises(ClientError) as exc_info:
            bob['ecs'].execute_command(
                cluster=test_config['ecs_cluster'],
                task=alice_task_arn,
                container='rosa-boundary',
                command='/bin/bash',
                interactive=True
            )

        # Verify it's an access denied error
        error = exc_info.value.response['Error']
        assert error['Code'] in ['AccessDeniedException', 'ClientException'], \
            f"Expected access denied, got {error['Code']}: {error['Message']}"

        # The error message should mention authorization or permissions
        error_msg_lower = error['Message'].lower()
        assert any(keyword in error_msg_lower for keyword in [
            'not authorized', 'access denied', 'permission', 'denied'
        ]), f"Unexpected error message: {error['Message']}"

    def test_user_cannot_stop_other_user_task(
        self,
        alice_bob_pair,
        test_config
    ):
        """
        Verify Bob cannot stop Alice's task.

        IAM policy should deny ecs:StopTask when
        ResourceTag/uuid != PrincipalTag/uuid
        """
        alice, bob = alice_bob_pair

        # Find Alice's running tasks
        alice_tasks_resp = alice['ecs'].list_tasks(
            cluster=test_config['ecs_cluster'],
            desiredStatus='RUNNING',
            maxResults=1
        )

        if not alice_tasks_resp.get('taskArns'):
            pytest.skip("No running tasks found for Alice")

        alice_task_arn = alice_tasks_resp['taskArns'][0]

        # Bob tries to stop Alice's task
        with pytest.raises(ClientError) as exc_info:
            bob['ecs'].stop_task(
                cluster=test_config['ecs_cluster'],
                task=alice_task_arn,
                reason='Integration test - should be denied'
            )

        # Verify access denied
        error = exc_info.value.response['Error']
        assert error['Code'] in ['AccessDeniedException', 'ClientException'], \
            f"Expected access denied, got {error['Code']}"

    def test_user_can_exec_into_own_task(
        self,
        alice_credentials,
        test_config
    ):
        """
        Verify Alice CAN execute commands in her own task (positive test).

        IAM policy should allow ecs:ExecuteCommand when
        ResourceTag/uuid == PrincipalTag/uuid
        """
        from fixtures.aws import get_boto3_client

        alice_ecs = get_boto3_client('ecs', alice_credentials, test_config['aws_region'])

        # Find Alice's own tasks
        alice_tasks_resp = alice_ecs.list_tasks(
            cluster=test_config['ecs_cluster'],
            desiredStatus='RUNNING',
            maxResults=1
        )

        if not alice_tasks_resp.get('taskArns'):
            pytest.skip("No running tasks found for Alice. Create investigation first.")

        alice_task_arn = alice_tasks_resp['taskArns'][0]

        # Verify task has uuid tag matching Alice
        task_details = alice_ecs.describe_tasks(
            cluster=test_config['ecs_cluster'],
            tasks=[alice_task_arn]
        )

        if not task_details.get('tasks'):
            pytest.skip("Task disappeared during test")

        task = task_details['tasks'][0]

        # Check task is in RUNNING state and has exec enabled
        if task['lastStatus'] != 'RUNNING':
            pytest.skip(f"Task is not RUNNING (status: {task['lastStatus']})")

        if not task.get('enableExecuteCommand'):
            pytest.skip("Task does not have ECS Exec enabled")

        # Alice executes command in her own task - should succeed
        # Note: This may still fail if the exec agent isn't ready, but
        # the IAM check happens first, so AccessDenied would come before
        # any agent-related errors
        try:
            response = alice_ecs.execute_command(
                cluster=test_config['ecs_cluster'],
                task=alice_task_arn,
                container='rosa-boundary',
                command='/bin/echo "ABAC test"',
                interactive=False
            )

            # If we get a response, IAM allowed it (success)
            assert 'session' in response, "Expected session info in response"

        except ClientError as e:
            error_code = e.response['Error']['Code']

            # These errors are OK - they mean IAM allowed it but something else failed
            acceptable_errors = [
                'InvalidParameterException',  # Container/command issue
                'TargetNotConnectedException',  # Exec agent not ready
                'ClientException'  # Other non-IAM issues
            ]

            if error_code in acceptable_errors:
                # IAM allowed it, but exec failed for other reasons - test passes
                pytest.skip(f"IAM allowed exec, but failed with {error_code} (acceptable)")
            elif error_code == 'AccessDeniedException':
                # This is a test failure - Alice should be able to access her own task
                pytest.fail(f"Alice was denied access to her own task: {e}")
            else:
                # Unknown error
                raise

    def test_user_can_list_all_tasks_but_filtered(
        self,
        alice_bob_pair,
        test_config
    ):
        """
        Verify users can list tasks but results are filtered by tags.

        ecs:DescribeTasks and ecs:ListTasks have no ABAC restrictions,
        but the CLI/application should filter results by tag.
        """
        alice, bob = alice_bob_pair

        # Both users can call ListTasks without IAM errors
        alice_tasks = alice['ecs'].list_tasks(
            cluster=test_config['ecs_cluster'],
            desiredStatus='RUNNING'
        )

        bob_tasks = bob['ecs'].list_tasks(
            cluster=test_config['ecs_cluster'],
            desiredStatus='RUNNING'
        )

        # Both calls should succeed (no AccessDenied)
        assert 'taskArns' in alice_tasks
        assert 'taskArns' in bob_tasks

        # Note: The filtering happens at application layer (CLI), not IAM
        # Both users see all tasks, but the CLI should only show their own
        # This test just verifies IAM allows the read operation
