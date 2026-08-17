import unittest
from app import create_app
from app.extensions import db
from app.models import BlockedIP, Incident
from app.services.core import block_ip, is_active_block
from datetime import datetime, timedelta, timezone


class TestConfig:
    TESTING=True
    SECRET_KEY="test"
    SQLALCHEMY_DATABASE_URI="sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS=False
    ATTEMPT_THRESHOLDS={"temporary":3,"long":5,"permanent":10}
    TEMP_BLOCK_DURATION=5
    LONG_BLOCK_DURATION=30
    CORRELATION_WINDOW=300


class SocTestCase(unittest.TestCase):
    def setUp(self):
        self.app=create_app(TestConfig)
        self.client=self.app.test_client()
    def login(self, username="analyst", password="analyst123"):
        return self.client.post('/login',data={"username":username,"password":password})
    def test_normal_simulation_persists_events(self):
        self.login()
        response=self.client.post('/api/simulation/start',json={"count":3})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.client.get('/api/events').get_json()['total'],3)
    def test_brute_force_creates_incident_and_block(self):
        self.login()
        self.client.post('/api/simulation/scenario',json={"scenario":"brute_force"})
        with self.app.app_context():
            self.assertEqual(Incident.query.count(),1)
            self.assertTrue(BlockedIP.query.filter_by(ip="192.168.1.100",status="ACTIVE").first())
    def test_rbac_blocks_viewer_firewall_mutation(self):
        self.login("viewer","viewer123")
        response=self.client.post('/api/firewall/block',json={"ip":"10.1.1.1"})
        self.assertEqual(response.status_code,403)
    def test_analyst_can_transition_incident(self):
        self.login()
        self.client.post('/api/simulation/scenario',json={"scenario":"web_attack"})
        incident=self.client.get('/api/incidents').get_json()[0]
        response=self.client.patch('/api/incidents/'+str(incident['id']),json={"status":"CONTAINED"})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.get_json()['status'],"CONTAINED")
    def test_whitelist_prevents_simulated_block(self):
        self.login("admin", "admin123")
        self.assertEqual(self.client.post('/api/firewall/whitelist',json={"ip":"10.1.1.1"}).status_code,201)
        response=self.client.post('/api/firewall/block',json={"ip":"10.1.1.1"})
        self.assertEqual(response.status_code,409)
    def test_expired_block_becomes_inactive(self):
        with self.app.app_context():
            item,_=block_ip("10.2.2.2","test",duration_minutes=1)
            item.expires_at=datetime.now(timezone.utc).replace(tzinfo=None)-timedelta(seconds=1)
            db.session.commit()
            self.assertFalse(is_active_block("10.2.2.2"))
            self.assertEqual(BlockedIP.query.filter_by(ip="10.2.2.2").first().status,"EXPIRED")
    def test_viewer_cannot_run_simulation_or_manage_rules(self):
        self.login("viewer","viewer123")
        self.assertEqual(self.client.post('/api/simulation/scenario',json={"scenario":"port_scan"}).status_code,403)
        self.assertEqual(self.client.post('/api/firewall/rules',json={"name":"deny","action":"DENY"}).status_code,403)
    def test_selected_scenario_creates_only_that_semantic_attack(self):
        self.login()
        response=self.client.post('/api/simulation/scenario',json={"scenario":"port_scan"})
        self.assertEqual(response.get_json()["scenario"],"port_scan")
        events=self.client.get('/api/events?per_page=50').get_json()["items"]
        self.assertTrue(events)
        self.assertTrue(all(event["attack_type"]=="Port Scan" for event in events))
    def test_normal_baseline_is_low_risk_and_allowed(self):
        self.login()
        self.client.post('/api/simulation/start',json={"count":30})
        events=self.client.get('/api/events?per_page=50').get_json()["items"]
        self.assertTrue(all(event["status"]=="NORMAL" for event in events))
        self.assertTrue(all(event["action"]=="ALLOW" for event in events))
        self.assertTrue(all(event["risk_score"]<30 for event in events))
    def test_block_enforced_after_relogin_and_unblock_resumes_policy(self):
        self.login()
        self.client.post('/api/firewall/block',json={"ip":"192.168.1.100"})
        self.client.get('/logout');self.login()
        self.client.post('/api/simulation/attack',json={"attack_type":"Brute Force"})
        blocked=self.client.get('/api/events?per_page=5').get_json()["items"][0]
        self.assertEqual(blocked["action"],"DROP")
        self.client.post('/api/firewall/unblock',json={"ip":"192.168.1.100"})
        self.client.post('/api/simulation/attack',json={"attack_type":"Brute Force"})
        self.assertNotEqual(self.client.get('/api/events?per_page=5').get_json()["items"][0]["action"],"DROP")
    def test_e2e_multi_stage_persistence_investigation_and_audit(self):
        self.login()
        self.client.post('/api/simulation/start',json={"count":10})
        response=self.client.post('/api/simulation/scenario',json={"scenario":"multi_stage"})
        self.assertEqual(response.status_code,200)
        incident=self.client.get('/api/incidents').get_json()[0]
        detail=self.client.get('/api/incidents/'+str(incident["id"])).get_json()
        self.assertGreater(len(detail["events"]),1)
        self.assertEqual(self.client.post('/api/incidents/'+str(incident["id"])+"/notes",json={"content":"Validated correlated synthetic activity."}).status_code,201)
        self.client.patch('/api/incidents/'+str(incident["id"]),json={"status":"INVESTIGATING"})
        self.client.patch('/api/incidents/'+str(incident["id"]),json={"status":"CONTAINED"})
        self.client.patch('/api/incidents/'+str(incident["id"]),json={"status":"RESOLVED"})
        self.client.get('/logout');self.login()
        detail=self.client.get('/api/incidents/'+str(incident["id"])).get_json()
        self.assertEqual(detail["status"],"RESOLVED")
        self.assertEqual(len(detail["notes"]),1)
        with self.app.app_context():
            self.assertGreater(Incident.query.count(),0)
    def test_admin_user_role_change_immediately_changes_permissions(self):
        self.login("admin","admin123")
        created=self.client.post('/api/users',json={"username":"change_me","password":"ChangeMe123","role":"VIEWER"})
        self.assertEqual(created.status_code,201);user_id=created.get_json()["id"]
        viewer=self.app.test_client();viewer.post('/login',data={"username":"change_me","password":"ChangeMe123"})
        self.assertEqual(viewer.post('/api/simulation/start',json={"count":1}).status_code,403)
        self.client.patch('/api/users/'+str(user_id),json={"role":"ANALYST"})
        self.assertEqual(viewer.post('/api/simulation/start',json={"count":1}).status_code,200)
        self.client.patch('/api/users/'+str(user_id),json={"role":"VIEWER"})
        self.assertEqual(viewer.post('/api/simulation/start',json={"count":1}).status_code,403)
    def test_disabled_account_and_password_reset_are_enforced(self):
        self.login("admin","admin123");user=self.client.post('/api/users',json={"username":"disabled","password":"Original123","role":"ANALYST"}).get_json()
        self.client.patch('/api/users/'+str(user["id"]),json={"status":"DISABLED"})
        self.assertEqual(self.app.test_client().post('/login',data={"username":"disabled","password":"Original123"}).status_code,200)
        self.client.patch('/api/users/'+str(user["id"]),json={"status":"ACTIVE","password":"Replacement123"})
        client=self.app.test_client();client.post('/login',data={"username":"disabled","password":"Original123"});self.assertEqual(client.post('/api/simulation/start',json={}).status_code,401)
        client=self.app.test_client();client.post('/login',data={"username":"disabled","password":"Replacement123"});self.assertEqual(client.post('/api/simulation/start',json={}).status_code,200)
    def test_settings_are_admin_only_and_change_detection_threshold(self):
        self.login("viewer","viewer123");self.assertEqual(self.client.get('/api/settings').status_code,403)
        self.client.get('/logout');self.login("admin","admin123")
        self.assertEqual(self.client.patch('/api/settings/BRUTE_FORCE_THRESHOLD',json={"value":3}).status_code,200)
        self.client.get('/logout');self.login()
        self.client.post('/api/simulation/attack',json={"attack_type":"Brute Force","count":4})
        self.assertGreater(len(self.client.get('/api/incidents').get_json()),0)

if __name__ == '__main__': unittest.main()
