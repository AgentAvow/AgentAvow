from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.database import get_db
from src.main import app


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


REGISTER_URL = "/api/v1/auth/register"
LOGIN_URL = "/api/v1/auth/login"
ME_URL = "/api/v1/auth/me"
FEED_URL = "/api/v1/feed/posts"
FLAG_URL = "/api/v1/moderation/flag"

USER_A = {
    "email": "mod_email_a@example.com",
    "password": "Str0ngP@ss",
    "display_name": "ModEmailUserA",
}
USER_B = {
    "email": "mod_email_b@example.com",
    "password": "Str0ngP@ss",
    "display_name": "ModEmailUserB",
}
ADMIN = {
    "email": "mod_email_admin@example.com",
    "password": "Str0ngP@ss",
    "display_name": "ModEmailAdmin",
}


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _setup_user(client: AsyncClient, user: dict) -> tuple[str, str]:
    """Register + login, return (token, entity_id)."""
    await client.post(REGISTER_URL, json=user)
    resp = await client.post(
        LOGIN_URL, json={"email": user["email"], "password": user["password"]}
    )
    token = resp.json()["access_token"]
    me = await client.get(ME_URL, headers=_auth(token))
    return token, me.json()["id"]


async def _make_admin(db, entity_id: str) -> None:
    from src.models import Entity

    entity = await db.get(Entity, uuid.UUID(entity_id))
    entity.is_admin = True
    await db.flush()


# --- Template loading tests ---


class TestModerationTemplates:
    """Test that moderation email templates load and render correctly."""

    def test_flag_notify_template_loads(self):
        from src.email import _load_template

        html = _load_template(
            "moderation_flag_notify.html",
            entity_name="TestUser",
            content_preview="Some bad content...",
            reason="harassment",
            appeal_url="http://example.com/appeal/123",
        )
        assert "TestUser" in html
        assert "Some bad content..." in html
        assert "harassment" in html
        assert "http://example.com/appeal/123" in html
        assert "AgentAvow" in html

    def test_resolved_template_loads(self):
        from src.email import _load_template

        html = _load_template(
            "moderation_resolved.html",
            entity_name="TestUser",
            content_preview="The flagged post text",
            decision="removed",
            reason="Violated community guidelines",
        )
        assert "TestUser" in html
        assert "The flagged post text" in html
        assert "removed" in html
        assert "Violated community guidelines" in html

    def test_appeal_received_template_loads(self):
        from src.email import _load_template

        html = _load_template(
            "moderation_appeal_received.html",
            entity_name="TestUser",
            content_preview="Post about AI agents",
        )
        assert "TestUser" in html
        assert "Post about AI agents" in html
        assert "under review" in html

    def test_appeal_decision_template_loads(self):
        from src.email import _load_template

        html = _load_template(
            "moderation_appeal_decision.html",
            entity_name="TestUser",
            decision="Appeal overturned",
            reason="Content did not violate guidelines",
        )
        assert "TestUser" in html
        assert "Appeal overturned" in html
        assert "Content did not violate guidelines" in html


# --- Email function unit tests ---


class TestModerationEmailFunctions:
    """Test the moderation email wrapper functions (with mocked send_email)."""

    @pytest.mark.asyncio
    async def test_send_moderation_flag_email(self):
        from src.email import send_moderation_flag_email

        with patch("src.email.send_email", new_callable=AsyncMock, return_value=True) as mock:
            result = await send_moderation_flag_email(
                to="user@test.com",
                entity_name="TestUser",
                content_preview="Bad content",
                reason="spam",
                appeal_url="http://localhost/appeal",
            )
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert call_args[0][0] == "user@test.com"
            assert "flagged" in call_args[0][1].lower()
            assert "TestUser" in call_args[0][2]

    @pytest.mark.asyncio
    async def test_send_moderation_resolved_email(self):
        from src.email import send_moderation_resolved_email

        with patch("src.email.send_email", new_callable=AsyncMock, return_value=True) as mock:
            result = await send_moderation_resolved_email(
                to="user@test.com",
                entity_name="TestUser",
                content_preview="Some post",
                decision="removed",
                reason="harassment",
            )
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert call_args[0][0] == "user@test.com"
            assert "decision" in call_args[0][1].lower() or "moderation" in call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_send_moderation_appeal_received_email(self):
        from src.email import send_moderation_appeal_received_email

        with patch("src.email.send_email", new_callable=AsyncMock, return_value=True) as mock:
            result = await send_moderation_appeal_received_email(
                to="user@test.com",
                entity_name="TestUser",
                content_preview="My post",
            )
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert call_args[0][0] == "user@test.com"
            assert "appeal" in call_args[0][1].lower()

    @pytest.mark.asyncio
    async def test_send_moderation_appeal_decision_email(self):
        from src.email import send_moderation_appeal_decision_email

        with patch("src.email.send_email", new_callable=AsyncMock, return_value=True) as mock:
            result = await send_moderation_appeal_decision_email(
                to="user@test.com",
                entity_name="TestUser",
                decision="Appeal overturned",
                reason="Content was fine",
            )
            assert result is True
            mock.assert_called_once()
            call_args = mock.call_args
            assert call_args[0][0] == "user@test.com"
            assert "appeal" in call_args[0][1].lower()
            assert "decision" in call_args[0][1].lower()


# --- Integration tests: emails sent from moderation endpoints ---


class TestModerationEmailIntegration:
    """Test that moderation router endpoints trigger email sends."""

    @pytest.mark.asyncio
    async def test_flag_creation_sends_email(self, client, db):
        """When a flag is created, the flagged entity gets an email."""
        tok_a, id_a = await _setup_user(client, USER_A)
        tok_b, id_b = await _setup_user(client, USER_B)

        # User B creates a post
        resp = await client.post(
            FEED_URL,
            json={"content": "Some questionable content here"},
            headers=_auth(tok_b),
        )
        assert resp.status_code == 201
        post_id = resp.json()["id"]

        # User A flags it
        with patch(
            "src.email.send_email", new_callable=AsyncMock, return_value=True,
        ) as mock_send:
            resp = await client.post(
                FLAG_URL,
                json={
                    "target_type": "post",
                    "target_id": post_id,
                    "reason": "spam",
                },
                headers=_auth(tok_a),
            )
            assert resp.status_code == 201

            # Verify email was sent to User B
            assert mock_send.call_count >= 1
            # Find the flag email call (subject contains "flagged")
            flag_calls = [
                c for c in mock_send.call_args_list
                if "flagged" in c[0][1].lower()
            ]
            assert len(flag_calls) >= 1
            assert flag_calls[0][0][0] == USER_B["email"]

    @pytest.mark.asyncio
    async def test_resolve_flag_sends_email(self, client, db):
        """When a flag is resolved, the flagged entity gets an email."""
        tok_a, id_a = await _setup_user(client, {
            "email": "resolve_a@example.com",
            "password": "Str0ngP@ss",
            "display_name": "ResolveA",
        })
        tok_b, id_b = await _setup_user(client, {
            "email": "resolve_b@example.com",
            "password": "Str0ngP@ss",
            "display_name": "ResolveB",
        })
        tok_admin, id_admin = await _setup_user(client, {
            "email": "resolve_admin@example.com",
            "password": "Str0ngP@ss",
            "display_name": "ResolveAdmin",
        })
        await _make_admin(db, id_admin)

        # B posts, A flags
        resp = await client.post(
            FEED_URL,
            json={"content": "Content to moderate"},
            headers=_auth(tok_b),
        )
        post_id = resp.json()["id"]

        resp = await client.post(
            FLAG_URL,
            json={"target_type": "post", "target_id": post_id, "reason": "spam"},
            headers=_auth(tok_a),
        )
        flag_id = resp.json()["id"]

        # Admin resolves
        with patch(
            "src.email.send_email", new_callable=AsyncMock, return_value=True,
        ) as mock_send:
            resp = await client.patch(
                f"/api/v1/moderation/flags/{flag_id}/resolve",
                json={"status": "dismissed", "resolution_note": "Not spam"},
                headers=_auth(tok_admin),
            )
            assert resp.status_code == 200

            # Verify resolved email was sent to User B
            resolved_calls = [
                c for c in mock_send.call_args_list
                if "decision" in c[0][1].lower() or "moderation" in c[0][1].lower()
            ]
            assert len(resolved_calls) >= 1
            assert resolved_calls[0][0][0] == "resolve_b@example.com"

    @pytest.mark.asyncio
    async def test_appeal_sends_received_email(self, client, db):
        """When an appeal is filed, the appellant gets a confirmation email."""
        tok_a, id_a = await _setup_user(client, {
            "email": "appeal_recv_a@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealRecvA",
        })
        tok_b, id_b = await _setup_user(client, {
            "email": "appeal_recv_b@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealRecvB",
        })
        tok_admin, id_admin = await _setup_user(client, {
            "email": "appeal_recv_admin@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealRecvAdmin",
        })
        await _make_admin(db, id_admin)

        # B posts, A flags, admin resolves with "removed"
        resp = await client.post(
            FEED_URL,
            json={"content": "Content that gets removed"},
            headers=_auth(tok_b),
        )
        post_id = resp.json()["id"]

        resp = await client.post(
            FLAG_URL,
            json={"target_type": "post", "target_id": post_id, "reason": "spam"},
            headers=_auth(tok_a),
        )
        flag_id = resp.json()["id"]

        await client.patch(
            f"/api/v1/moderation/flags/{flag_id}/resolve",
            json={"status": "removed", "resolution_note": "Spam confirmed"},
            headers=_auth(tok_admin),
        )

        # B appeals
        with patch(
            "src.email.send_email", new_callable=AsyncMock, return_value=True,
        ) as mock_send:
            resp = await client.post(
                f"/api/v1/moderation/flags/{flag_id}/appeal",
                json={"reason": "This was not spam, please reconsider"},
                headers=_auth(tok_b),
            )
            assert resp.status_code == 201

            # Verify appeal received email was sent
            appeal_calls = [
                c for c in mock_send.call_args_list
                if "appeal" in c[0][1].lower() and "received" in c[0][1].lower()
            ]
            assert len(appeal_calls) >= 1

    @pytest.mark.asyncio
    async def test_appeal_decision_sends_email(self, client, db):
        """When an appeal is decided, the appellant gets a decision email."""
        tok_a, id_a = await _setup_user(client, {
            "email": "appeal_dec_a@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealDecA",
        })
        tok_b, id_b = await _setup_user(client, {
            "email": "appeal_dec_b@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealDecB",
        })
        tok_admin, id_admin = await _setup_user(client, {
            "email": "appeal_dec_admin@example.com",
            "password": "Str0ngP@ss",
            "display_name": "AppealDecAdmin",
        })
        await _make_admin(db, id_admin)

        # B posts, A flags, admin resolves with "removed"
        resp = await client.post(
            FEED_URL,
            json={"content": "Content for appeal decision test"},
            headers=_auth(tok_b),
        )
        post_id = resp.json()["id"]

        resp = await client.post(
            FLAG_URL,
            json={"target_type": "post", "target_id": post_id, "reason": "spam"},
            headers=_auth(tok_a),
        )
        flag_id = resp.json()["id"]

        await client.patch(
            f"/api/v1/moderation/flags/{flag_id}/resolve",
            json={"status": "removed", "resolution_note": "Spam confirmed"},
            headers=_auth(tok_admin),
        )

        # B appeals
        resp = await client.post(
            f"/api/v1/moderation/flags/{flag_id}/appeal",
            json={"reason": "Not spam, legitimate content"},
            headers=_auth(tok_b),
        )
        appeal_id = resp.json()["id"]

        # Admin resolves appeal (overturn)
        with patch(
            "src.email.send_email", new_callable=AsyncMock, return_value=True,
        ) as mock_send:
            resp = await client.patch(
                f"/api/v1/moderation/appeals/{appeal_id}",
                json={"action": "overturn", "note": "Content was fine"},
                headers=_auth(tok_admin),
            )
            assert resp.status_code == 200

            # Verify appeal decision email was sent to User B
            decision_calls = [
                c for c in mock_send.call_args_list
                if "appeal" in c[0][1].lower() and "decision" in c[0][1].lower()
            ]
            assert len(decision_calls) >= 1
            assert decision_calls[0][0][0] == "appeal_dec_b@example.com"

    @pytest.mark.asyncio
    async def test_email_failure_does_not_break_flag(self, client, db):
        """If email sending fails, the flag API still succeeds."""
        tok_a, id_a = await _setup_user(client, {
            "email": "fail_a@example.com",
            "password": "Str0ngP@ss",
            "display_name": "FailA",
        })
        tok_b, id_b = await _setup_user(client, {
            "email": "fail_b@example.com",
            "password": "Str0ngP@ss",
            "display_name": "FailB",
        })

        # B posts
        resp = await client.post(
            FEED_URL,
            json={"content": "Content that triggers email failure"},
            headers=_auth(tok_b),
        )
        post_id = resp.json()["id"]

        # Mock email to raise an exception
        with patch(
            "src.email.send_email",
            new_callable=AsyncMock,
            side_effect=Exception("SMTP down"),
        ):
            resp = await client.post(
                FLAG_URL,
                json={"target_type": "post", "target_id": post_id, "reason": "spam"},
                headers=_auth(tok_a),
            )
            # Flag creation should still succeed
            assert resp.status_code == 201
            assert resp.json()["status"] == "pending"


# --- Helper function tests ---


class TestGetTargetEntityInfo:
    """Test the _get_target_entity_info helper function."""

    @pytest.mark.asyncio
    async def test_post_target_returns_author_info(self, client, db):
        tok_b, id_b = await _setup_user(client, {
            "email": "helper_b@example.com",
            "password": "Str0ngP@ss",
            "display_name": "HelperB",
        })

        # Create a post
        resp = await client.post(
            FEED_URL,
            json={"content": "Test post for helper function"},
            headers=_auth(tok_b),
        )
        post_id = resp.json()["id"]

        # Create a flag object pointing at the post
        from src.models import ModerationFlag, ModerationReason, ModerationStatus

        flag = ModerationFlag(
            id=uuid.uuid4(),
            reporter_entity_id=None,
            target_type="post",
            target_id=uuid.UUID(post_id),
            reason=ModerationReason.SPAM,
            status=ModerationStatus.PENDING,
        )
        db.add(flag)
        await db.flush()

        from src.api.moderation_router import _get_target_entity_info

        email, name, preview = await _get_target_entity_info(db, flag)
        assert email == "helper_b@example.com"
        assert name == "HelperB"
        assert "Test post for helper function" in preview

    @pytest.mark.asyncio
    async def test_entity_target_returns_entity_info(self, client, db):
        tok_b, id_b = await _setup_user(client, {
            "email": "helper_ent@example.com",
            "password": "Str0ngP@ss",
            "display_name": "HelperEnt",
        })

        from src.models import ModerationFlag, ModerationReason, ModerationStatus

        flag = ModerationFlag(
            id=uuid.uuid4(),
            reporter_entity_id=None,
            target_type="entity",
            target_id=uuid.UUID(id_b),
            reason=ModerationReason.SPAM,
            status=ModerationStatus.PENDING,
        )
        db.add(flag)
        await db.flush()

        from src.api.moderation_router import _get_target_entity_info

        email, name, preview = await _get_target_entity_info(db, flag)
        assert email == "helper_ent@example.com"
        assert name == "HelperEnt"
        assert "HelperEnt" in preview
