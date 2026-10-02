package com.sandeeprathore.vmpatchagent.match;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import com.sandeeprathore.vmpatchagent.inventory.InstalledApp;
import com.sandeeprathore.vmpatchagent.match.AppCatalogProperties.Entry;

import org.springframework.stereotype.Component;

@Component
public class AppCatalog {

	private record Compiled(Entry entry, Pattern pattern) {
	}

	private final List<Compiled> entries;

	public AppCatalog(AppCatalogProperties properties) {
		this.entries = properties.apps().stream().map(e -> new Compiled(e, Pattern.compile(e.namePattern()))).toList();
	}

	public Optional<Entry> lookup(InstalledApp app) {
		if (app.name() == null) {
			return Optional.empty();
		}
		return entries.stream().filter(c -> c.pattern().matcher(app.name()).find()).map(Compiled::entry).findFirst();
	}

	/** The distinct NVD products to fetch for these installed apps. */
	public Set<String> productsFor(Collection<InstalledApp> apps) {
		var products = new LinkedHashSet<String>();
		apps.forEach(app -> lookup(app).ifPresent(entry -> products.add(entry.cpe())));
		return products;
	}

}
