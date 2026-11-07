import os
os.environ['DATABASE_URL']='sqlite:///./test_relay.db'
os.environ['SEED_SAMPLE_DATA']='false'
from fastapi.testclient import TestClient
from app.main import app, Base, engine
Base.metadata.create_all(engine)
def test_incident_resolution_memory():
 with TestClient(app) as c:
  x=c.post('/api/v1/incidents',json={'title':'Checkout database timeout','service':'checkout-api','description':'Connection timeout after deploy'});assert x.status_code==201
  i=x.json();assert i['incident_id'].startswith('INC-')
  assert c.post(f"/api/v1/incidents/{i['id']}/resolve",json={'root_cause':'Pool exhausted','resolution_steps':'Increase pool','lessons_learned':'Monitor pool'}).status_code==200
  y=c.post('/api/v1/incidents',json={'title':'Checkout connection timeout','service':'checkout-api','description':'Database connections exhausted'}).json()
  a=c.post(f"/api/v1/incidents/{y['id']}/analyze").json();assert a['mode']=='fallback';assert a['historical_incidents']
