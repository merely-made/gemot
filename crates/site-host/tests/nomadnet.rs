use gemot_site_host::{LocalServer, Site, SiteFormat};
use retinue::{endpoint::Endpoint, identity::PrivateIdentity, nomadnet::fetch_page};
use std::{fs, time::Duration};

#[tokio::test]
async fn micron_serves_saved_bytes_replaces_snapshot_and_closes_interface() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let temp = tempfile::tempdir().unwrap();
        let site = Site::create_for(&temp.path().join("micron"), SiteFormat::Micron).unwrap();
        let path = site.page_path("index.mu").unwrap();
        let original = b"> Saved heading\r\nraw `!source`!\r\n";
        fs::write(&path, original).unwrap();
        let server = LocalServer::start(site.publication().unwrap(), 0).unwrap();
        let address = server.address();
        let destination = server.nomadnet_destination().unwrap();
        let client = Endpoint::new(PrivateIdentity::from_secret_bytes(&[0x71; 64]));
        client.attach_tcp_client(address).await.unwrap();
        client.request_path(destination);
        let peer = loop {
            if let Some(peer) = client.resolve(destination) {
                break peer;
            }
            client.next_announcement().await.unwrap();
        };
        let mut session = client.open_resource(destination, peer).await.unwrap();
        let request = retinue::request::Request::new(b"/page/index.mu", Vec::new(), 0.0);
        fs::write(&path, b"unpublished draft").unwrap();
        assert_eq!(
            fetch_page(&client, destination, peer, b"/page/index.mu")
                .await
                .unwrap(),
            original
        );
        let large = vec![b'x'; 128 * 1024];
        fs::write(&path, &large).unwrap();
        server.replace(site.publication().unwrap()).unwrap();
        assert_eq!(session.request(&request).await.unwrap().data, large);
        // A proof confirms Resource bytes, but does not authorize closing the
        // peer's reusable page link or discarding its next request.
        fs::write(&path, original).unwrap();
        server.replace(site.publication().unwrap()).unwrap();
        assert_eq!(session.request(&request).await.unwrap().data, original);
        fs::write(&path, &large).unwrap();
        server.replace(site.publication().unwrap()).unwrap();
        assert_eq!(
            fetch_page(&client, destination, peer, b"/page/index.mu")
                .await
                .unwrap(),
            large
        );
        assert_eq!(fs::read(&path).unwrap(), large);
        let other = Site::create(&temp.path().join("scroll")).unwrap();
        assert!(server.replace(other.publication().unwrap()).is_err());
        drop(server);
        client.close();
        assert!(std::net::TcpStream::connect(address).is_err());
    })
    .await
    .expect("NomadNet saved-snapshot lifecycle must complete");
}
