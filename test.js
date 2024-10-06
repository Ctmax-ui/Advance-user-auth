import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  vus: 10000,
  duration: '30s',
  cloud: {
    projectID: 3718084,
    name: 'Test (06/10/2024-10:29:03)'
  },
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<200'], // 95% of requests should be below 200ms
  },
};

export default function() {
  http.get('http://localhost:3000/api/v1/userhasaccess');
  sleep(1);
}