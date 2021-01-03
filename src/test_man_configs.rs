use tokio;

#[tokio::test]
/* Extract examples from the config manpage.  Examples are between .EX/.EE pairs.  Once extracted,
 * run the config parser over them to make sure they're valid.
 */
async fn man_page_example_configs() {
    use tokio::io::AsyncReadExt as _;

    let mut contents = Default::default();
    tokio::fs::File::open("man/erbium.conf.5")
        .await
        .unwrap()
        .read_to_string(&mut contents)
        .await
        .unwrap();
    let mut example: String = Default::default();
    let mut in_example = false;
    let mut examples = 0;

    for line in contents.split("\n") {
        if line == ".EX" {
            example = "".into();
            in_example = true;
        } else if line == ".EE" {
            println!("Parsing example: {}", example);
            super::config::load_config_from_string_for_test(&example).unwrap();
            in_example = false;
            examples += 1;
        } else if in_example {
            example += line;
            example += "\n";
        }
    }
    assert_ne!(examples, 0); /* We need to test at least one example */
}
